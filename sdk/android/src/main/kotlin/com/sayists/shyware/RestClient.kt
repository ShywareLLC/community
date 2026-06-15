package com.sayists.shyware

/**
 * RestClient pairs StoreClient + ChatClient from the same manifest.
 * shyrest-v1 surfaces both store and chat operations through a single entry point.
 */
class RestClient private constructor(
    private val _storeClient: StoreClient,
    private val _chatClient: ChatClient,
    val manifest: ShyConfig,
) {
    companion object {
        fun from(
            manifest: ShyConfig,
            sealerKeyProvider: SealerKeyProvider? = null,
        ): RestClient {
            val store = StoreClient.fromRaw(manifest, sealerKeyProvider)
            val chat = ChatClient.fromRaw(manifest)
            return RestClient(store, chat, manifest)
        }
    }

    fun getStoreClient(): StoreClient = _storeClient
    fun getChatClient(): ChatClient = _chatClient

    // Delegate store operations
    suspend fun storeSubmission(scopingId: String, plaintext: String, category: String) =
        _storeClient.storeSubmission(scopingId, plaintext, category)

    suspend fun revealAndDecryptStore(scopingId: String, submissionId: String) =
        _storeClient.revealAndDecryptStore(scopingId, submissionId)

    suspend fun deleteStore(scopingId: String, submissionId: String) =
        _storeClient.deleteStore(scopingId, submissionId)

    // Delegate chat operations
    suspend fun createMailbox(label: String, address: String, routeHint: String? = null) =
        _chatClient.createMailbox(label, address, routeHint)

    suspend fun queueDispatch(
        mailboxId: String,
        recipientAddress: String,
        subject: String,
        body: String,
        contentClass: String,
    ) = _chatClient.queueDispatch(mailboxId, recipientAddress, subject, body, contentClass)

    suspend fun getInbox(mailboxId: String) = _chatClient.getInbox(mailboxId)
}
