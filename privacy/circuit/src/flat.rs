//! The flat calldata layout of a spend proof, read by the Solidity verifier (SpendVerifier.sol).
//!
//! Integers are big-endian; a field element is its canonical value as 4 bytes; an extension element
//! is its 8 basis coefficients as 4-byte values, coefficient 7 first, so one 32-byte word holds
//! coefficient i in bits [32 i, 32 i + 32); a digest is 32 bytes.
//!
//! ```text
//!   digest trace, digest quotient, digest random
//!   ext[W] trace at zeta, ext[W] trace at zeta * g, ext[8][8] quotient chunks, ext[8] random
//!   ext[11][8] random-codeword openings: random, trace at zeta, trace at zeta * g, 8 quotient chunks
//!   u32 batch grinding witness, digest[rounds] commit-phase commitments, ext[16] final polynomial,
//!   u32 query grinding witness
//!   3 input batches (random, trace, quotient), each: for every query, for every matrix, the row then
//!     its 4 salt elements; then u16 sibling count and the siblings
//!   every commit round: for every query, arity - 1 extension siblings then 4 salt elements; then u16
//!     sibling count and the siblings
//! ```
//!
//! The trace height is fixed (2^7 rows, 2^8 with the zero-knowledge extension), so it is not carried.
//! Neither are the out-of-domain and commit-phase grinding witnesses: with zero bits Plonky3 accepts
//! only zero there, so the encoder asserts zero and the decoder writes zero.

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use p3_fri::{BatchMultiOpening, CommitPhaseMultiStep, FriProof, fold_schedule};
use p3_merkle_tree::PrunedMerklePaths;
use p3_symmetric::MerkleCap;
use p3_uni_stark::{Commitments, OpenedValues, Proof};

use crate::{Challenge, Config, LOG_BLOWUP, LOG_FINAL_POLY_LEN, LOG_ROWS, MAX_LOG_ARITY, NUM_QUERIES, NUM_RANDOM_CODEWORDS, TRACE_WIDTH, Val};

pub const SALT: usize = 4;
pub const EXT: usize = 8;
pub const QUOTIENT_CHUNKS: usize = 8;
pub const FINAL_POLY_LEN: usize = 1 << LOG_FINAL_POLY_LEN;
/// log2 of the committed trace height (the zero-knowledge extension doubles it).
pub const DEGREE_BITS: usize = LOG_ROWS + 1;

pub const O_TRACE: usize = 0;
pub const O_QUOT: usize = 32;
pub const O_RAND: usize = 64;
pub const O_TL: usize = 96;
pub const O_TN: usize = O_TL + TRACE_WIDTH * 32;
pub const O_QC: usize = O_TN + TRACE_WIDTH * 32;
pub const O_RV: usize = O_QC + QUOTIENT_CHUNKS * EXT * 32;
pub const O_RCW: usize = O_RV + EXT * 32;
pub const RCW_SETS: usize = 3 + QUOTIENT_CHUNKS;
pub const O_BPW: usize = O_RCW + RCW_SETS * NUM_RANDOM_CODEWORDS * 32;
pub const O_COMMITS: usize = O_BPW + 4;

type Digest32 = [u8; 32];
type SaltsAndPaths = (Vec<Vec<Vec<Val>>>, PrunedMerklePaths<u8, 32>);

/// Widths of the committed matrices of the three input batches, random-codeword columns included.
pub fn batch_widths() -> [Vec<usize>; 3] {
    let r = NUM_RANDOM_CODEWORDS;
    [vec![EXT + r], vec![TRACE_WIDTH + r], vec![EXT + r; QUOTIENT_CHUNKS]]
}

/// Opening points per matrix of each batch: the trace opens at zeta and zeta * g.
pub fn batch_points() -> [Vec<usize>; 3] {
    [vec![1], vec![2], vec![1; QUOTIENT_CHUNKS]]
}

/// FRI's folding schedule (log arities) for the fixed height.
pub fn schedule() -> Vec<usize> {
    fold_schedule(&[DEGREE_BITS + LOG_BLOWUP], LOG_BLOWUP + LOG_FINAL_POLY_LEN, MAX_LOG_ARITY)
}

struct Writer(Vec<u8>);

impl Writer {
    fn u16(&mut self, v: usize) {
        self.0.extend_from_slice(&u16::try_from(v).expect("fits u16").to_be_bytes());
    }
    fn val(&mut self, v: Val) {
        self.0.extend_from_slice(&v.as_canonical_u32().to_be_bytes());
    }
    fn ext(&mut self, e: &Challenge) {
        let c: &[Val] = BasedVectorSpace::<Val>::as_basis_coefficients_slice(e);
        for i in (0..EXT).rev() {
            self.val(c[i]);
        }
    }
    fn root(&mut self, cap: &MerkleCap<Val, Digest32>) {
        assert_eq!(cap.num_roots(), 1, "cap height 0 carries one root");
        self.0.extend_from_slice(&cap.roots()[0]);
    }
}

pub fn encode(proof: &Proof<Config>) -> Vec<u8> {
    let mut w = Writer(Vec::new());
    let ov = &proof.opened_values;
    let (rand_cws, fri) = &proof.opening_proof;
    assert_eq!(proof.degree_bits, DEGREE_BITS, "fixed trace height");
    assert!(ov.preprocessed.is_none(), "no preprocessed trace");
    assert_eq!(proof.ood_pow_witness, Val::ZERO, "zero out-of-domain grinding admits only a zero witness");
    assert!(fri.commit_pow_witnesses.iter().all(|x| *x == Val::ZERO), "zero commit grinding admits only zero witnesses");
    w.root(&proof.commitments.trace);
    w.root(&proof.commitments.quotient_chunks);
    w.root(proof.commitments.random.as_ref().expect("hiding PCS"));
    assert_eq!(ov.trace_local.len(), TRACE_WIDTH);
    ov.trace_local.iter().for_each(|e| w.ext(e));
    let next = ov.trace_next.as_ref().expect("the AIR reads the next row");
    assert_eq!(next.len(), TRACE_WIDTH);
    next.iter().for_each(|e| w.ext(e));
    assert_eq!(ov.quotient_chunks.len(), QUOTIENT_CHUNKS);
    for ch in &ov.quotient_chunks {
        assert_eq!(ch.len(), EXT);
        ch.iter().for_each(|e| w.ext(e));
    }
    let random = ov.random.as_ref().expect("hiding PCS");
    assert_eq!(random.len(), EXT);
    random.iter().for_each(|e| w.ext(e));
    assert_eq!(rand_cws.len(), 3);
    for (round, points) in rand_cws.iter().zip(batch_points()) {
        assert_eq!(round.len(), points.len());
        for (mat, &np) in round.iter().zip(&points) {
            assert_eq!(mat.len(), np);
            for pt in mat {
                assert_eq!(pt.len(), NUM_RANDOM_CODEWORDS);
                pt.iter().for_each(|e| w.ext(e));
            }
        }
    }
    w.val(fri.batch_pow_witness);
    let arities = schedule();
    assert_eq!(fri.commit_phase_commits.len(), arities.len());
    fri.commit_phase_commits.iter().for_each(|c| w.root(c));
    assert_eq!(fri.final_poly.len(), FINAL_POLY_LEN);
    fri.final_poly.iter().for_each(|e| w.ext(e));
    w.val(fri.query_pow_witness);
    assert_eq!(fri.input_openings.len(), 3);
    for (batch, widths) in fri.input_openings.iter().zip(batch_widths()) {
        let (salts, paths) = &batch.opening_proof;
        assert_eq!(batch.opened_values.len(), NUM_QUERIES);
        assert_eq!(salts.len(), NUM_QUERIES);
        for (rows, ss) in batch.opened_values.iter().zip(salts) {
            assert_eq!(rows.len(), widths.len());
            assert_eq!(ss.len(), widths.len());
            for ((row, salt), &width) in rows.iter().zip(ss).zip(&widths) {
                assert_eq!(row.len(), width);
                assert_eq!(salt.len(), SALT);
                row.iter().for_each(|v| w.val(*v));
                salt.iter().for_each(|v| w.val(*v));
            }
        }
        w.u16(paths.sibling_hashes.len());
        paths.sibling_hashes.iter().for_each(|d| w.0.extend_from_slice(d));
    }
    assert_eq!(fri.commit_phase_openings.len(), arities.len());
    for (step, &log_arity) in fri.commit_phase_openings.iter().zip(&arities) {
        let (salts, paths) = &step.opening_proof;
        assert_eq!(step.sibling_values.len(), NUM_QUERIES);
        assert_eq!(salts.len(), NUM_QUERIES);
        for (sib, ss) in step.sibling_values.iter().zip(salts) {
            assert_eq!(sib.len(), (1 << log_arity) - 1);
            assert_eq!(ss.len(), 1);
            assert_eq!(ss[0].len(), SALT);
            sib.iter().for_each(|e| w.ext(e));
            ss[0].iter().for_each(|v| w.val(*v));
        }
        w.u16(paths.sibling_hashes.len());
        paths.sibling_hashes.iter().for_each(|d| w.0.extend_from_slice(d));
    }
    w.0
}

#[derive(Debug)]
pub struct DecodeError;

struct Reader<'a> {
    d: &'a [u8],
    p: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], DecodeError> {
        let s = self.d.get(self.p..self.p + n).ok_or(DecodeError)?;
        self.p += n;
        Ok(s)
    }
    fn u16(&mut self) -> Result<usize, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]) as usize)
    }
    fn val(&mut self) -> Result<Val, DecodeError> {
        let b = self.take(4)?;
        let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        if v >= Val::ORDER_U32 {
            return Err(DecodeError);
        }
        Ok(Val::from_u32(v))
    }
    fn vals(&mut self, n: usize) -> Result<Vec<Val>, DecodeError> {
        (0..n).map(|_| self.val()).collect()
    }
    fn ext(&mut self) -> Result<Challenge, DecodeError> {
        let mut c = self.vals(EXT)?;
        c.reverse();
        Ok(Challenge::from_basis_coefficients_slice(&c).expect("8 coefficients"))
    }
    fn exts(&mut self, n: usize) -> Result<Vec<Challenge>, DecodeError> {
        (0..n).map(|_| self.ext()).collect()
    }
    fn cap(&mut self) -> Result<MerkleCap<Val, Digest32>, DecodeError> {
        Ok(MerkleCap::new(vec![self.take(32)?.try_into().unwrap()]))
    }
    fn siblings(&mut self) -> Result<PrunedMerklePaths<u8, 32>, DecodeError> {
        let n = self.u16()?;
        let sibling_hashes = (0..n).map(|_| Ok(self.take(32)?.try_into().unwrap())).collect::<Result<_, _>>()?;
        Ok(PrunedMerklePaths { sibling_hashes })
    }
}

/// The Plonky3 proof a flat encoding carries; errors on anything Plonky3 could not represent
/// (non-canonical elements, wrong lengths).
pub fn decode(d: &[u8]) -> Result<Proof<Config>, DecodeError> {
    let mut r = Reader { d, p: 0 };
    let trace = r.cap()?;
    let quotient = r.cap()?;
    let random_commit = r.cap()?;
    let trace_local = r.exts(TRACE_WIDTH)?;
    let trace_next = r.exts(TRACE_WIDTH)?;
    let quotient_chunks = (0..QUOTIENT_CHUNKS).map(|_| r.exts(EXT)).collect::<Result<_, _>>()?;
    let random = r.exts(EXT)?;
    let mut rand_cws = Vec::new();
    for points in batch_points() {
        let mut round = Vec::new();
        for np in points {
            round.push((0..np).map(|_| r.exts(NUM_RANDOM_CODEWORDS)).collect::<Result<Vec<_>, _>>()?);
        }
        rand_cws.push(round);
    }
    let batch_pow_witness = r.val()?;
    let arities = schedule();
    let commit_phase_commits = arities.iter().map(|_| r.cap()).collect::<Result<_, _>>()?;
    let final_poly = r.exts(FINAL_POLY_LEN)?;
    let query_pow_witness = r.val()?;
    let mut input_openings = Vec::new();
    for widths in batch_widths() {
        let mut opened = Vec::new();
        let mut salts = Vec::new();
        for _ in 0..NUM_QUERIES {
            let mut rows = Vec::new();
            let mut ss = Vec::new();
            for &width in &widths {
                rows.push(r.vals(width)?);
                ss.push(r.vals(SALT)?);
            }
            opened.push(rows);
            salts.push(ss);
        }
        let proof: SaltsAndPaths = (salts, r.siblings()?);
        input_openings.push(BatchMultiOpening { opened_values: opened, opening_proof: proof });
    }
    let mut commit_phase_openings = Vec::new();
    for &log_arity in &arities {
        let mut sibling_values = Vec::new();
        let mut salts = Vec::new();
        for _ in 0..NUM_QUERIES {
            sibling_values.push(r.exts((1 << log_arity) - 1)?);
            salts.push(vec![r.vals(SALT)?]);
        }
        let proof: SaltsAndPaths = (salts, r.siblings()?);
        commit_phase_openings.push(CommitPhaseMultiStep { sibling_values, opening_proof: proof });
    }
    if r.p != d.len() {
        return Err(DecodeError);
    }
    let fri = FriProof {
        batch_pow_witness,
        commit_phase_commits,
        commit_pow_witnesses: vec![Val::ZERO; arities.len()],
        input_openings,
        commit_phase_openings,
        final_poly,
        query_pow_witness,
    };
    Ok(Proof {
        commitments: Commitments { trace, quotient_chunks: quotient, random: Some(random_commit) },
        opened_values: OpenedValues { trace_local, trace_next: Some(trace_next), preprocessed: None, quotient_chunks, random: Some(random) },
        opening_proof: (rand_cws, fri),
        degree_bits: DEGREE_BITS,
        ood_pow_witness: Val::ZERO,
    })
}
