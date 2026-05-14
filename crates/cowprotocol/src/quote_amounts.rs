//! Quote-to-signed-order amount projection with full fee composition.
//!
//! Mirrors `@cowprotocol/cow-sdk`'s `getQuoteAmountsAndCosts` (TypeScript)
//! byte-for-byte: every intermediate stage (`beforeAllFees`,
//! `afterProtocolFees`, `afterNetworkCosts`, `afterPartnerFees`,
//! `afterSlippage`) and the final `amountsToSign` derive from the same
//! arithmetic the TS path uses, so callers that mix a partner fee with a
//! protocol fee get the same `buyAmount` the orderbook expects.
//!
//! ## Why this exists
//!
//! [`crate::OrderQuoteResponse::to_signed_order_data`] applies only the
//! basic `sellAmount + feeAmount` adjustment documented at [api §"Step 3"].
//! When the caller layers a partner fee on top of a quote that also
//! carries a protocol fee, the partner-fee base must be computed against
//! the spot price (`beforeAllFees.buyAmount`), which itself depends on
//! the protocol-fee amount. Skipping the protocol-fee leg
//! understates the partner-fee base and overstates the final
//! `buyAmount`; the orderbook rejects or under-fills the resulting
//! order. The TypeScript SDK fixed this in
//! [`cow-sdk` #867](https://github.com/cowprotocol/cow-sdk/pull/867);
//! this module is the Rust port (against upstream [cow-sdk @
//! `00c3dbd4`](https://github.com/cowprotocol/cow-sdk/blob/00c3dbd41c086ff9a51d5e5a30648615d4c66d0d/packages/order-book/src/quoteAmountsAndCosts/getQuoteAmountsAndCosts.ts),
//! pinned in `parity/source-lock.toml`). Its conformance test asserts
//! the same `1_970_090_045_022_511_257` / `1_970_100_000_000_000_000`
//! divergence the TS test locks.
//!
//! ## Order-of-operations
//!
//! ```text
//! beforeAllFees
//!   └─ afterProtocolFees   (protocol fee deducted from buy / added to sell)
//!        └─ afterNetworkCosts   (network costs already baked in by the API)
//!             └─ afterPartnerFees   (partner-fee base = beforeAllFees)
//!                  └─ afterSlippage    (slippage on the non-fixed side)
//! ```
//!
//! [api §"Step 3"]: https://docs.cow.fi/cow-protocol/howto/integrate/api#step-3-compute-the-amounts-to-sign

use alloy_primitives::U256;

use crate::{Error, error::Result, order::OrderKind};

/// Bps denominator (10_000 = 100%).
const ONE_HUNDRED_BPS: u64 = 10_000;
/// Scale applied to `protocol_fee_bps` so the on-wire decimal string
/// (e.g. `"0.3"`) round-trips through integer arithmetic with five
/// fractional digits of precision, matching the TS SDK's
/// `Math.round(protocolFeeBps * 100_000)`.
const HUNDRED_THOUSANDS: u64 = 100_000;

/// A pair of sell / buy amounts at a specific fee-application stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Amounts {
    /// `sellAmount` at this stage, in atomic units.
    pub sell_amount: U256,
    /// `buyAmount` at this stage, in atomic units.
    pub buy_amount: U256,
}

/// Cost breakdown for a single quote, in the same shape the TS SDK's
/// `QuoteAmountsAndCosts.costs` exposes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuoteCosts {
    /// Network cost in `sell_token` atomic units (echoes the quote's
    /// `feeAmount`).
    pub network_fee_in_sell: U256,
    /// Network cost projected into `buy_token` atomic units via the
    /// quote's price ratio.
    pub network_fee_in_buy: U256,
    /// Absolute partner-fee amount, in the surplus token
    /// (`buy_token` for SELL orders, `sell_token` for BUY orders).
    pub partner_fee_amount: U256,
    /// Partner fee in basis points (0 if no partner fee was applied).
    pub partner_fee_bps: u32,
    /// Absolute protocol-fee amount, in the surplus token.
    pub protocol_fee_amount: U256,
    /// Protocol fee scaled by `100_000` (i.e. `5` for an integer
    /// bps value of `5`, `30_000` for `"0.3"`). Use
    /// [`protocol_fee_bps_scale`] when reasoning about precision.
    pub protocol_fee_bps_scaled: u64,
}

/// Full amount projection plus cost breakdown, mirroring the TS SDK's
/// `QuoteAmountsAndCosts` return type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuoteAmountsAndCosts {
    /// `true` for SELL quotes, `false` for BUY.
    pub is_sell: bool,
    /// Amounts at the spot-price stage: protocol fee added back on
    /// SELL, removed on BUY. Network costs are *included* on the sell
    /// side for SELL orders and *not* added on the buy side for BUY
    /// orders, exactly as the orderbook reports them.
    pub before_all_fees: Amounts,
    /// Amounts after the protocol fee but before network costs.
    pub after_protocol_fees: Amounts,
    /// Amounts as returned by the `/quote` endpoint (for SELL) or with
    /// network costs added to `sellAmount` (for BUY).
    pub after_network_costs: Amounts,
    /// Amounts after deducting partner fee from the surplus side.
    pub after_partner_fees: Amounts,
    /// Amounts after slippage is applied to the non-fixed side.
    pub after_slippage: Amounts,
    /// The amounts that should be signed and submitted: SELL uses
    /// `before_all_fees.sell` and `after_slippage.buy`; BUY uses
    /// `after_slippage.sell` and `before_all_fees.buy`.
    pub amounts_to_sign: Amounts,
    /// Cost breakdown.
    pub costs: QuoteCosts,
}

/// Inputs to [`compute`].
#[derive(Clone, Copy, Debug)]
pub struct QuoteAmountsParams<'a> {
    /// Quote direction (SELL or BUY).
    pub kind: OrderKind,
    /// `quote.sellAmount` from the orderbook response.
    pub sell_amount: U256,
    /// `quote.buyAmount` from the orderbook response.
    pub buy_amount: U256,
    /// `quote.feeAmount` (network cost) from the response.
    pub fee_amount: U256,
    /// Partner fee in basis points, applied on top of the protocol
    /// adjustment. `0` skips the partner-fee leg.
    pub partner_fee_bps: u32,
    /// Slippage tolerance in basis points, applied to the non-fixed
    /// side (SELL: buy; BUY: sell). `0` skips the slippage leg.
    pub slippage_bps: u32,
    /// Decimal-string `protocolFeeBps` echoed by the quote (e.g.
    /// `"0.3"`). `None` and `Some("0")` are equivalent and skip the
    /// protocol-fee leg.
    pub protocol_fee_bps: Option<&'a str>,
}

/// Compute every fee-application stage and the `amountsToSign` for a
/// quote response, matching the TS SDK's `getQuoteAmountsAndCosts`.
///
/// Returns [`Error::InvalidProtocolFeeBps`] when the protocol-fee
/// string fails to parse and [`Error::QuoteSellAmountZero`] when the
/// quote reports `sellAmount = 0`.
///
/// ```
/// use alloy_primitives::U256;
/// use cowprotocol::{OrderKind, quote_amounts};
///
/// let res = quote_amounts::compute(quote_amounts::QuoteAmountsParams {
///     kind: OrderKind::Sell,
///     sell_amount: U256::from(1_000_000_000_000_000_000u128),
///     buy_amount: U256::from(2_000_000_000_000_000_000u128),
///     fee_amount: U256::ZERO,
///     partner_fee_bps: 100,
///     slippage_bps: 50,
///     protocol_fee_bps: Some("5"),
/// })
/// .unwrap();
/// assert_eq!(
///     res.amounts_to_sign.buy_amount,
///     U256::from(1_970_090_045_022_511_257u128),
/// );
/// ```
pub fn compute(params: QuoteAmountsParams<'_>) -> Result<QuoteAmountsAndCosts> {
    let QuoteAmountsParams {
        kind,
        sell_amount,
        buy_amount,
        fee_amount,
        partner_fee_bps,
        slippage_bps,
        protocol_fee_bps,
    } = params;

    let is_sell = matches!(kind, OrderKind::Sell);
    let protocol_fee_bps_scaled = parse_protocol_fee_bps(protocol_fee_bps)?;

    if sell_amount.is_zero() {
        return Err(Error::QuoteSellAmountZero);
    }
    let network_fee_in_buy = mul_div(buy_amount, fee_amount, sell_amount);

    let protocol_fee_amount = protocol_fee_amount(
        kind,
        sell_amount,
        buy_amount,
        fee_amount,
        protocol_fee_bps_scaled,
    );

    let before_all_fees = if is_sell {
        Amounts {
            sell_amount: sell_amount.saturating_add(fee_amount),
            buy_amount: buy_amount
                .saturating_add(network_fee_in_buy)
                .saturating_add(protocol_fee_amount),
        }
    } else {
        Amounts {
            sell_amount: sell_amount.saturating_sub(protocol_fee_amount),
            buy_amount,
        }
    };

    let after_protocol_fees = if is_sell {
        Amounts {
            sell_amount: before_all_fees.sell_amount,
            buy_amount: before_all_fees
                .buy_amount
                .saturating_sub(protocol_fee_amount),
        }
    } else {
        Amounts {
            sell_amount,
            buy_amount: before_all_fees.buy_amount,
        }
    };

    let after_network_costs = if is_sell {
        Amounts {
            sell_amount,
            buy_amount,
        }
    } else {
        Amounts {
            sell_amount: sell_amount.saturating_add(fee_amount),
            buy_amount: after_protocol_fees.buy_amount,
        }
    };

    let surplus_base = if is_sell {
        before_all_fees.buy_amount
    } else {
        before_all_fees.sell_amount
    };
    let partner_fee_amount = if partner_fee_bps == 0 {
        U256::ZERO
    } else {
        mul_div(
            surplus_base,
            U256::from(partner_fee_bps),
            U256::from(ONE_HUNDRED_BPS),
        )
    };
    let after_partner_fees = if is_sell {
        Amounts {
            sell_amount: after_network_costs.sell_amount,
            buy_amount: after_network_costs
                .buy_amount
                .saturating_sub(partner_fee_amount),
        }
    } else {
        Amounts {
            sell_amount: after_network_costs
                .sell_amount
                .saturating_add(partner_fee_amount),
            buy_amount: after_network_costs.buy_amount,
        }
    };

    let after_slippage = if is_sell {
        let slip = mul_div(
            after_partner_fees.buy_amount,
            U256::from(slippage_bps),
            U256::from(ONE_HUNDRED_BPS),
        );
        Amounts {
            sell_amount: after_partner_fees.sell_amount,
            buy_amount: after_partner_fees.buy_amount.saturating_sub(slip),
        }
    } else {
        let slip = mul_div(
            after_partner_fees.sell_amount,
            U256::from(slippage_bps),
            U256::from(ONE_HUNDRED_BPS),
        );
        Amounts {
            sell_amount: after_partner_fees.sell_amount.saturating_add(slip),
            buy_amount: after_partner_fees.buy_amount,
        }
    };

    let amounts_to_sign = if is_sell {
        Amounts {
            sell_amount: before_all_fees.sell_amount,
            buy_amount: after_slippage.buy_amount,
        }
    } else {
        Amounts {
            sell_amount: after_slippage.sell_amount,
            buy_amount: before_all_fees.buy_amount,
        }
    };

    Ok(QuoteAmountsAndCosts {
        is_sell,
        before_all_fees,
        after_protocol_fees,
        after_network_costs,
        after_partner_fees,
        after_slippage,
        amounts_to_sign,
        costs: QuoteCosts {
            network_fee_in_sell: fee_amount,
            network_fee_in_buy,
            partner_fee_amount,
            partner_fee_bps,
            protocol_fee_amount,
            protocol_fee_bps_scaled,
        },
    })
}

/// Scale factor applied to `protocol_fee_bps` to keep five decimal
/// digits of precision (10⁵). Exported so consumers that compute their
/// own protocol-fee amounts use the same denominator the SDK does.
pub const fn protocol_fee_bps_scale() -> u64 {
    HUNDRED_THOUSANDS
}

fn parse_protocol_fee_bps(input: Option<&str>) -> Result<u64> {
    let Some(raw) = input else {
        return Ok(0);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    if trimmed.starts_with('-') {
        return Err(Error::InvalidProtocolFeeBps {
            value: raw.to_owned(),
            reason: "must be non-negative",
        });
    }
    let (int_part, frac_part) = trimmed
        .find('.')
        .map_or((trimmed, ""), |i| (&trimmed[..i], &trimmed[i + 1..]));
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(Error::InvalidProtocolFeeBps {
            value: raw.to_owned(),
            reason: "empty value",
        });
    }
    let int_val: u64 = if int_part.is_empty() {
        0
    } else {
        int_part.parse().map_err(|_| Error::InvalidProtocolFeeBps {
            value: raw.to_owned(),
            reason: "integer part is not a decimal number",
        })?
    };
    let frac_scaled = if frac_part.is_empty() {
        0u64
    } else {
        if !frac_part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::InvalidProtocolFeeBps {
                value: raw.to_owned(),
                reason: "fractional part is not a decimal number",
            });
        }
        // Pad to 6 digits so we can read 5 digits of result + 1 digit
        // for half-away-from-zero rounding, matching `Math.round`.
        let mut padded = String::with_capacity(6);
        padded.push_str(frac_part);
        while padded.len() < 6 {
            padded.push('0');
        }
        let five: u64 = padded[..5]
            .parse()
            .map_err(|_| Error::InvalidProtocolFeeBps {
                value: raw.to_owned(),
                reason: "fractional part overflows internal scale",
            })?;
        let round_digit = padded.as_bytes()[5] - b'0';
        if round_digit >= 5 { five + 1 } else { five }
    };
    int_val
        .checked_mul(HUNDRED_THOUSANDS)
        .and_then(|v| v.checked_add(frac_scaled))
        .ok_or(Error::InvalidProtocolFeeBps {
            value: raw.to_owned(),
            reason: "value too large for internal scale",
        })
}

fn protocol_fee_amount(
    kind: OrderKind,
    sell_amount: U256,
    buy_amount: U256,
    fee_amount: U256,
    bps_scaled: u64,
) -> U256 {
    if bps_scaled == 0 {
        return U256::ZERO;
    }
    let bps_big = U256::from(bps_scaled);
    let scale = U256::from(ONE_HUNDRED_BPS).saturating_mul(U256::from(HUNDRED_THOUSANDS));
    match kind {
        OrderKind::Sell => {
            // protocolFeeInBuy = buyAmount * bps / (10_000 * 100_000 - bps)
            let denom = scale.saturating_sub(bps_big);
            if denom.is_zero() {
                return U256::ZERO;
            }
            mul_div(buy_amount, bps_big, denom)
        }
        OrderKind::Buy => {
            // protocolFeeInSell = (sellAmount + feeAmount) * bps
            //                     / (10_000 * 100_000 + bps)
            let denom = scale.saturating_add(bps_big);
            let base = sell_amount.saturating_add(fee_amount);
            if denom.is_zero() {
                return U256::ZERO;
            }
            mul_div(base, bps_big, denom)
        }
    }
}

#[inline]
fn mul_div(a: U256, b: U256, c: U256) -> U256 {
    if c.is_zero() {
        return U256::ZERO;
    }
    a.saturating_mul(b) / c
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locks the exact divergence the upstream TypeScript SDK fix
    /// (`cow-sdk` #867, "fix(trading): take protocol fee into account")
    /// pinned in `packages/trading/src/postCoWProtocolTrade.test.ts`.
    ///
    /// Default quote: `sellAmount = 1e18`, `buyAmount = 2e18`,
    /// `feeAmount = 0`, kind = SELL, slippage = 50 bps, partner fee =
    /// 100 bps. With `protocolFeeBps = 0` the signed `buyAmount` is
    /// `1_970_100_000_000_000_000`; with `protocolFeeBps = 5` it
    /// becomes `1_970_090_045_022_511_257`. Both numbers are checked
    /// here against our port.
    #[test]
    fn matches_ts_pr_867_partner_plus_protocol_fee_divergence() {
        let base = QuoteAmountsParams {
            kind: OrderKind::Sell,
            sell_amount: U256::from(1_000_000_000_000_000_000u128),
            buy_amount: U256::from(2_000_000_000_000_000_000u128),
            fee_amount: U256::ZERO,
            partner_fee_bps: 100,
            slippage_bps: 50,
            protocol_fee_bps: None,
        };

        let without = compute(base).unwrap();
        assert_eq!(
            without.amounts_to_sign.buy_amount,
            U256::from(1_970_100_000_000_000_000u128),
            "buyAmount without protocol fee must match TS PR #867 baseline",
        );

        let with_protocol = compute(QuoteAmountsParams {
            protocol_fee_bps: Some("5"),
            ..base
        })
        .unwrap();
        assert_eq!(
            with_protocol.amounts_to_sign.buy_amount,
            U256::from(1_970_090_045_022_511_257u128),
            "buyAmount with protocolFeeBps=5 must match TS PR #867 expected value",
        );
        assert!(
            with_protocol.amounts_to_sign.buy_amount < without.amounts_to_sign.buy_amount,
            "protocol fee enlarges the partner-fee base, so signed buy_amount must drop",
        );
    }

    #[test]
    fn sell_order_no_fees_passes_amounts_through_to_signing() {
        let res = compute(QuoteAmountsParams {
            kind: OrderKind::Sell,
            sell_amount: U256::from(1_000_000_000_000_000_000u128),
            buy_amount: U256::from(2_000_000_000_000_000_000u128),
            fee_amount: U256::ZERO,
            partner_fee_bps: 0,
            slippage_bps: 0,
            protocol_fee_bps: None,
        })
        .unwrap();
        assert_eq!(
            res.amounts_to_sign.sell_amount,
            U256::from(1_000_000_000_000_000_000u128)
        );
        assert_eq!(
            res.amounts_to_sign.buy_amount,
            U256::from(2_000_000_000_000_000_000u128)
        );
        assert_eq!(res.costs.partner_fee_amount, U256::ZERO);
        assert_eq!(res.costs.protocol_fee_amount, U256::ZERO);
    }

    #[test]
    fn sell_order_folds_fee_amount_into_signed_sell() {
        let res = compute(QuoteAmountsParams {
            kind: OrderKind::Sell,
            sell_amount: U256::from(1_000_000_000_000_000_000u128),
            buy_amount: U256::from(2_000_000_000_000_000_000u128),
            fee_amount: U256::from(1_000_000_000_000_000u128),
            partner_fee_bps: 0,
            slippage_bps: 0,
            protocol_fee_bps: None,
        })
        .unwrap();
        assert_eq!(
            res.amounts_to_sign.sell_amount,
            U256::from(1_001_000_000_000_000_000u128),
        );
    }

    #[test]
    fn buy_order_applies_slippage_to_sell_side() {
        let res = compute(QuoteAmountsParams {
            kind: OrderKind::Buy,
            sell_amount: U256::from(1_000_000_000_000_000_000u128),
            buy_amount: U256::from(2_000_000_000_000_000_000u128),
            fee_amount: U256::ZERO,
            partner_fee_bps: 0,
            slippage_bps: 50,
            protocol_fee_bps: None,
        })
        .unwrap();
        // sell becomes sell * (1 + 0.005) = 1.005e18; buy passes through.
        assert_eq!(
            res.amounts_to_sign.sell_amount,
            U256::from(1_005_000_000_000_000_000u128),
        );
        assert_eq!(
            res.amounts_to_sign.buy_amount,
            U256::from(2_000_000_000_000_000_000u128)
        );
    }

    #[test]
    fn protocol_fee_bps_accepts_decimal_string() {
        assert_eq!(parse_protocol_fee_bps(None).unwrap(), 0);
        assert_eq!(parse_protocol_fee_bps(Some("")).unwrap(), 0);
        assert_eq!(parse_protocol_fee_bps(Some("0")).unwrap(), 0);
        assert_eq!(parse_protocol_fee_bps(Some("5")).unwrap(), 500_000);
        assert_eq!(parse_protocol_fee_bps(Some("0.3")).unwrap(), 30_000);
        assert_eq!(parse_protocol_fee_bps(Some("0.30000")).unwrap(), 30_000);
        // Round-half-away-from-zero, matching `Math.round`.
        assert_eq!(parse_protocol_fee_bps(Some("0.000005")).unwrap(), 1);
        assert_eq!(parse_protocol_fee_bps(Some("0.000004")).unwrap(), 0);
    }

    #[test]
    fn protocol_fee_bps_rejects_negative_or_garbage() {
        assert!(matches!(
            parse_protocol_fee_bps(Some("-1")),
            Err(Error::InvalidProtocolFeeBps { .. }),
        ));
        assert!(matches!(
            parse_protocol_fee_bps(Some("abc")),
            Err(Error::InvalidProtocolFeeBps { .. }),
        ));
        assert!(matches!(
            parse_protocol_fee_bps(Some("0.x")),
            Err(Error::InvalidProtocolFeeBps { .. }),
        ));
    }

    #[test]
    fn zero_sell_amount_is_refused_instead_of_dividing_by_zero() {
        let err = compute(QuoteAmountsParams {
            kind: OrderKind::Sell,
            sell_amount: U256::ZERO,
            buy_amount: U256::from(1_u64),
            fee_amount: U256::ZERO,
            partner_fee_bps: 0,
            slippage_bps: 0,
            protocol_fee_bps: None,
        })
        .unwrap_err();
        assert!(matches!(err, Error::QuoteSellAmountZero));
    }
}
