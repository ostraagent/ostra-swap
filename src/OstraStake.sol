// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

/// @title OstraStake
/// @notice Locks OSTRA for at least LOCK_DURATION so that an account pays a lower Ostra Swap fee (design v0.4,
///         "Ostra Swap", decided 20 Oct 2026). Each locker has one position: the OSTRA it locked and the accounts the
///         lock counts for (its beneficiaries, at most MAX_BENEFICIARIES: a holder's wallet and its vaults, which
///         cannot lock themselves; an agent's output goes to a vault per token, and OstraRouter charges an escrow
///         swap's fee to the account that gets the output). Every lock, and every change of beneficiaries, locks
///         the whole position again for LOCK_DURATION; after that the locker may withdraw it, all of it, back to
///         itself. While the position is locked its beneficiaries may only grow (a new vault added); one is removed
///         only once the lock has run out (independent review, 20 Oct 2026: changing them at will let one position
///         lend its tier to any account, one transaction at a time), so a position serves at most
///         MAX_BENEFICIARIES accounts per LOCK_DURATION. OSTRA counts only while it
///         sits here, so a discount cannot be borrowed for one transaction. No owner, no upgrade: the tiers below
///         never change.
contract OstraStake is ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    /// @notice How long a position stays locked after its last lock or change of beneficiaries: 7 days.
    uint256 public constant LOCK_DURATION = 7 days;
    /// @notice The most accounts one position counts for.
    uint256 public constant MAX_BENEFICIARIES = 8;

    /// @notice Ostra Swap fees, in bps of the hub amount, by the OSTRA locked for an account (18 decimals).
    uint16 public constant FEE_BASE_BPS = 20;
    uint256 public constant TIER1_AMOUNT = 100_000e18;
    uint16 public constant FEE_TIER1_BPS = 15;
    uint256 public constant TIER2_AMOUNT = 250_000e18;
    uint16 public constant FEE_TIER2_BPS = 10;
    uint256 public constant TIER3_AMOUNT = 500_000e18;
    uint16 public constant FEE_TIER3_BPS = 0;

    IERC20 public immutable OSTRA;

    struct Position {
        uint128 amount;
        uint40 unlockAt;
        address[] beneficiaries;
    }

    mapping(address locker => Position) private _positions;
    /// @notice The OSTRA locked for each account, summed over the positions naming it.
    mapping(address account => uint256) public lockedFor;

    event Locked(address indexed locker, uint256 added, uint256 amount, uint40 unlockAt, address[] beneficiaries);
    event Withdrawn(address indexed locker, uint256 amount, address[] beneficiaries);

    error BadBeneficiaries();
    error NothingToLock();
    error StillLocked(uint40 unlockAt);
    error NothingToWithdraw();
    error AmountTooLarge();
    error BeneficiariesLocked(uint40 unlockAt);

    constructor(address ostra) {
        OSTRA = IERC20(ostra);
    }

    /// @notice The caller's position: OSTRA locked, when it unlocks, and the accounts it counts for.
    function positionOf(address locker) external view returns (uint256 amount, uint40 unlockAt, address[] memory beneficiaries) {
        Position storage p = _positions[locker];
        return (p.amount, p.unlockAt, p.beneficiaries);
    }

    /// @notice Adds `amount` OSTRA (0: none) to the caller's position, makes it count for `beneficiaries` (1 to
    ///         MAX_BENEFICIARIES distinct, non-zero accounts; they replace the previous ones; while the position is
    ///         locked they must include every previous one), and locks the whole position for LOCK_DURATION
    ///         from now. The amount added is what arrived, so a token that keeps part of
    ///         a transfer is counted as it is.
    function lock(uint256 amount, address[] calldata beneficiaries) external nonReentrant {
        uint256 n = beneficiaries.length;
        if (n == 0 || n > MAX_BENEFICIARIES) revert BadBeneficiaries();
        for (uint256 i; i < n; i++) {
            if (beneficiaries[i] == address(0)) revert BadBeneficiaries();
            for (uint256 k; k < i; k++) {
                if (beneficiaries[k] == beneficiaries[i]) revert BadBeneficiaries();
            }
        }
        Position storage p = _positions[msg.sender];
        bool same = _same(p.beneficiaries, beneficiaries);
        if (amount == 0 && (p.amount == 0 || same)) revert NothingToLock();
        if (!same && p.amount != 0 && block.timestamp < p.unlockAt && !_includes(beneficiaries, p.beneficiaries)) {
            revert BeneficiariesLocked(p.unlockAt);
        }
        uint256 added;
        if (amount != 0) {
            uint256 before = OSTRA.balanceOf(address(this));
            OSTRA.safeTransferFrom(msg.sender, address(this), amount);
            added = OSTRA.balanceOf(address(this)) - before;
        }
        uint256 total = uint256(p.amount) + added;
        if (total > type(uint128).max) revert AmountTooLarge();
        for (uint256 i; i < p.beneficiaries.length; i++) {
            lockedFor[p.beneficiaries[i]] -= p.amount;
        }
        for (uint256 i; i < n; i++) {
            lockedFor[beneficiaries[i]] += total;
        }
        uint40 unlockAt = uint40(block.timestamp + LOCK_DURATION);
        p.amount = uint128(total);
        p.unlockAt = unlockAt;
        p.beneficiaries = beneficiaries;
        emit Locked(msg.sender, added, total, unlockAt, beneficiaries);
    }

    /// @notice Sends the caller's whole position back to it, once its lock has run out.
    function withdraw() external nonReentrant {
        Position storage p = _positions[msg.sender];
        uint256 amount = p.amount;
        if (amount == 0) revert NothingToWithdraw();
        if (block.timestamp < p.unlockAt) revert StillLocked(p.unlockAt);
        address[] memory beneficiaries = p.beneficiaries;
        for (uint256 i; i < beneficiaries.length; i++) {
            lockedFor[beneficiaries[i]] -= amount;
        }
        delete _positions[msg.sender];
        OSTRA.safeTransfer(msg.sender, amount);
        emit Withdrawn(msg.sender, amount, beneficiaries);
    }

    /// @notice The Ostra Swap fee for `account`, in bps of the hub amount.
    function feeBps(address account) public view returns (uint16) {
        return feeBpsFor(lockedFor[account]);
    }

    /// @notice The fee tier of `locked` OSTRA.
    function feeBpsFor(uint256 locked) public pure returns (uint16) {
        if (locked >= TIER3_AMOUNT) return FEE_TIER3_BPS;
        if (locked >= TIER2_AMOUNT) return FEE_TIER2_BPS;
        if (locked >= TIER1_AMOUNT) return FEE_TIER1_BPS;
        return FEE_BASE_BPS;
    }

    /// @dev Whether `list` names every account in `previous`.
    function _includes(address[] calldata list, address[] storage previous) private view returns (bool) {
        for (uint256 i; i < previous.length; i++) {
            address a = previous[i];
            bool found;
            for (uint256 k; k < list.length; k++) {
                if (list[k] == a) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
        return true;
    }

    function _same(address[] storage a, address[] calldata b) private view returns (bool) {
        if (a.length != b.length) return false;
        for (uint256 i; i < b.length; i++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}
