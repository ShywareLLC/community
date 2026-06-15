package com.sayists.shyware

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ShyConfig(
    @SerialName("contract_version") val contractVersion: String,
    val app: AppConfig,
    val api: ApiConfig,
    val identity: IdentityConfig,
    val signing: SigningConfig,
    @SerialName("anon_layer") val anonLayer: AnonLayerConfig,
    val receipts: ReceiptsConfig? = null,
    val deployment: DeploymentConfig,
    val wire: WireConfig? = null,
    val custody: CustodyConfig? = null,
    val contracts: ContractsConfig? = null,
    val financing: ContractsConfig? = null,
    val governance: GovernanceConfig? = null,
    val execution: ExecutionConfig? = null,
    val store: StoreConfig? = null,
    val messaging: MessagingConfig? = null,
    val sealer: SealerConfig? = null,
    val stream: StreamConfig? = null,
    val lots: LotsConfig? = null,
)

@Serializable
data class AppConfig(
    val id: String,
    @SerialName("chain_id") val chainId: String? = null,
)

@Serializable
data class ApiConfig(
    @SerialName("base_url") val baseUrl: String,
    @SerialName("submit_base_url") val submitBaseUrl: String? = null,
    @SerialName("requires_auth") val requiresAuth: Boolean = false,
    @SerialName("auth_scheme") val authScheme: String? = null,  // "play_integrity" | "firebase_bearer" | null
)

@Serializable
data class IdentityConfig(
    val provider: String,
    val mode: String,
    @SerialName("issuer_did") val issuerDid: String? = null,
    @SerialName("workflow_id") val workflowId: String? = null,
    @SerialName("recommended_idv") val recommendedIdv: String? = null,
    @SerialName("kyc_required") val kycRequired: Boolean = false,
    @SerialName("byoid_policy") val byoidPolicy: String? = null,
)

@Serializable
data class SigningConfig(
    val required: Boolean,
    val backend: String,
    @SerialName("validator_key_id") val validatorKeyId: String? = null,
    @SerialName("tally_key_id") val tallyKeyId: String? = null,
)

@Serializable
data class AnonLayerConfig(
    @SerialName("black_box_required") val blackBoxRequired: Boolean,
    @SerialName("required_flows") val requiredFlows: List<String>,
)

@Serializable
data class ReceiptsConfig(
    @SerialName("match_store") val matchStore: String,
    @SerialName("user_access") val userAccess: String,
    @SerialName("double_vote_enforcement") val doubleVoteEnforcement: String,
    /** ISO 3166-1 alpha-2 country codes considered high-risk. The calling app resolves
     *  the device IP to a country code and sets network.hostile = true if present. */
    @SerialName("high_risk_region_blocklist") val highRiskRegionBlocklist: List<String> = emptyList(),
)

@Serializable
data class DeploymentConfig(
    @SerialName("default_posture") val defaultPosture: String,
    @SerialName("runtime_fallbacks") val runtimeFallbacks: RuntimeFallbacks,
    /** Path relative to api.base_url for operator-pushed posture override. Null = disabled. */
    @SerialName("posture_endpoint") val postureEndpoint: String? = null,
    /** Whether users in non-hostile contexts may set their own posture preference. */
    @SerialName("allow_user_posture_override") val allowUserPostureOverride: Boolean = false,
)

@Serializable
data class RuntimeFallbacks(
    @SerialName("write_only_on_missing_play_integrity") val writeOnlyOnMissingPlayIntegrity: Boolean = false,
    @SerialName("write_only_on_untrusted_device_attestation") val writeOnlyOnUntrustedDeviceAttestation: Boolean = false,
    @SerialName("write_only_on_hostile_network") val writeOnlyOnHostileNetwork: Boolean = false,
    @SerialName("write_only_on_hsm_unavailable") val writeOnlyOnHSMUnavailable: Boolean = false,
)

// MARK: - Domain config blocks

@Serializable
data class WireConfig(
    @SerialName("asset_id") val assetId: String? = null,
    @SerialName("wrapper_mode") val wrapperMode: String? = null,
    val provider: String? = null,
    @SerialName("provider_config") val providerConfig: WireProviderConfig? = null,
    @SerialName("operator_mint_burn") val operatorMintBurn: Boolean = false,
    @SerialName("reconcile_authority") val reconcileAuthority: String? = null,
    @SerialName("supported_networks") val supportedNetworks: List<String> = emptyList(),
    @SerialName("backing_asset") val backingAsset: String? = null,
    @SerialName("issuer_name") val issuerName: String? = null,
)

@Serializable
data class WireProviderConfig(
    val mode: String? = null,
    @SerialName("intent_path") val intentPath: String? = null,
    @SerialName("settlement_asset") val settlementAsset: String? = null,
    @SerialName("supported_rails") val supportedRails: List<String> = listOf("blockchain"),
    @SerialName("requires_operator_review") val requiresOperatorReview: Boolean = true,
)

@Serializable
data class CustodyConfig(
    @SerialName("asset_id") val assetId: String? = null,
    @SerialName("policy_source") val policySource: String? = null,
    @SerialName("unit_of_measure") val unitOfMeasure: String? = null,
    @SerialName("demurrage_policy") val demurragePolicy: String? = null,
    @SerialName("redemption_mode") val redemptionMode: String? = null,
    @SerialName("redemption_routing") val redemptionRouting: String? = null,
    @SerialName("transfer_layer") val transferLayer: String? = null,
    @SerialName("evidence_requirements") val evidenceRequirements: List<String> = emptyList(),
    @SerialName("operator_mint_burn") val operatorMintBurn: Boolean = false,
)

@Serializable
data class ContractsConfig(
    @SerialName("transfer_layer") val transferLayer: String? = null,
    @SerialName("contract_key_id") val contractKeyId: String? = null,
)

@Serializable
data class GovernanceConfig(
    @SerialName("membership_sources") val membershipSources: List<String> = emptyList(),
    @SerialName("weighting_mode") val weightingMode: String? = null,
    @SerialName("privacy_mode") val privacyMode: String? = null,
    @SerialName("proposal_classes") val proposalClasses: List<String> = emptyList(),
    @SerialName("transfer_layer") val transferLayer: String? = null,
)

@Serializable
data class ExecutionConfig(
    @SerialName("default_mode") val defaultMode: String? = null,
    val adapters: List<String> = emptyList(),
    @SerialName("canonical_queue") val canonicalQueue: Boolean = false,
)

@Serializable
data class StoreConfig(
    @SerialName("secret_categories") val secretCategories: List<String> = emptyList(),
    @SerialName("recovery_mode") val recoveryMode: String? = null,
    @SerialName("payload_encryption") val payloadEncryption: PayloadEncryptionConfig? = null,
    @SerialName("selective_disclosure") val selectiveDisclosure: Boolean = false,
    @SerialName("enumeration_protection") val enumerationProtection: String? = null,
    val sealer: SealerModeConfig? = null,
)

@Serializable
data class PayloadEncryptionConfig(
    val mode: String? = null,
)

@Serializable
data class MessagingConfig(
    @SerialName("payload_model") val payloadModel: String? = null,
    @SerialName("audit_model") val auditModel: String? = null,
    @SerialName("allowed_payload_formats") val allowedPayloadFormats: List<String> = emptyList(),
    @SerialName("surface_model") val surfaceModel: String? = null,
    @SerialName("mailbox_model") val mailboxModel: String? = null,
    @SerialName("delivery_model") val deliveryModel: String? = null,
    @SerialName("retention_policy") val retentionPolicy: String? = null,
)

@Serializable
data class SealerConfig(
    val mode: String? = null,
    val enabled: Boolean = false,
)

@Serializable
data class SealerModeConfig(
    val mode: String? = null,
)

@Serializable
data class StreamConfig(
    @SerialName("stream_mode") val streamMode: String? = null,
    @SerialName("allowed_content_classes") val allowedContentClasses: List<String> = emptyList(),
)

@Serializable
data class LotsConfig(
    @SerialName("market_operator") val marketOperator: String? = null,
    @SerialName("sale_modes") val saleModes: List<String> = emptyList(),
    @SerialName("open_mode") val openMode: String? = null,
    @SerialName("bid_visibility") val bidVisibility: String? = null,
    @SerialName("reserve_funding_mode") val reserveFundingMode: String? = null,
    @SerialName("settlement_asset_id") val settlementAssetId: String? = null,
)

// Runtime response models

@Serializable
data class Poll(
    @SerialName("poll_id") val pollId: String,
    val question: String,
    val options: List<String>,
    @SerialName("voting_method") val votingMethod: String,
    @SerialName("start_time") val startTime: Long,
    @SerialName("end_time") val endTime: Long,
    val status: String,
)

@Serializable
data class Tally(
    @SerialName("poll_id") val pollId: String,
    val counts: Map<String, Long>,
    @SerialName("total_votes") val totalVotes: Long,
    @SerialName("confirmed_count") val confirmedCount: Long,
    @SerialName("vote_merkle_root") val voteMerkleRoot: String,
    @SerialName("voter_merkle_root") val voterMerkleRoot: String,
    val signature: String,
    @SerialName("public_key") val publicKey: String,
)

@Serializable
data class VoteRecord(
    @SerialName("ballot_id") val ballotId: String,
    val choices: List<String>,
)

typealias KeyboxClient = StoreClient
