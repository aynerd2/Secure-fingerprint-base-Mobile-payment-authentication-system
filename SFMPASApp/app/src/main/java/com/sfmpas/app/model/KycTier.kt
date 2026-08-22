package com.sfmpas.app.model

/**
 * CBN KYC tiers as applied by SFMPAS, selected from the transaction value.
 *
 *   < ₦50,000            Tier 1 — fingerprint only
 *   ₦50,000 – ₦200,000   Tier 2 — fingerprint + liveness (PAD)
 *   > ₦200,000           Tier 3 — fingerprint + liveness + enhanced verification
 *
 * Boundaries are inclusive at the top of Tier 2: exactly ₦50,000 and exactly
 * ₦200,000 both fall in Tier 2.
 */
enum class KycTier(
    val displayName: String,
    val requirement: String,
    val requiresLiveness: Boolean,
    val requiresEnhanced: Boolean,
) {
    TIER_1(
        displayName = "Tier 1",
        requirement = "Fingerprint only",
        requiresLiveness = false,
        requiresEnhanced = false,
    ),
    TIER_2(
        displayName = "Tier 2",
        requirement = "Fingerprint + liveness check",
        requiresLiveness = true,
        requiresEnhanced = false,
    ),
    TIER_3(
        displayName = "Tier 3",
        requirement = "Fingerprint + liveness + enhanced verification",
        requiresLiveness = true,
        requiresEnhanced = true,
    );

    companion object {
        const val TIER_1_CEILING = 50_000L
        const val TIER_2_CEILING = 200_000L

        fun forAmount(amountNaira: Long): KycTier = when {
            amountNaira < TIER_1_CEILING -> TIER_1
            amountNaira <= TIER_2_CEILING -> TIER_2
            else -> TIER_3
        }
    }
}
