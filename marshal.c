
inline BYTE* pack_TPMA_SESSION(BYTE* ptr, const TPMA_SESSION attr)
{
	return pack_BYTE(ptr, attr);
}

inline BYTE* pack_TPMI_ALG_HASH(BYTE* ptr, const TPMI_ALG_HASH *hash)
{
	return pack_UINT16(ptr, hash);
}


inline BYTE* pack_TPM2B_DIGEST(BYTE* ptr, const TPM2B_DIGEST *digest)
{
	ptr += pack_UINT16(ptr, digest->size);
	ptr += pack_TPM_BUFFER(ptr, digest->buffer, size);
	return ptr;
}

inline BYTE* pack_TPM2B_NONCE(BYTE* ptr, const TPM2B_NONCE *nonce)
{
	return pack_TPM2B_DIGEST(ptr, nonce);
}

inline BYTE* pack_TPM2B_AUTH(BYTE* ptr, const TPM2B_AUTH *auth)
{
	return pack_TPM2B_DIGEST(ptr, auth);
}

inline BYTE* pack_TPM2B_DATA(BYTE* ptr, const TPM2B_DATA *data)
{
	return pack_TPM2B_DIGEST(ptr, data);
}
inline BYTE* pack_TPM2B_SENSITIVE_DATA(BYTE* ptr, const TPM2B_SENSITIVE_DATA *data)
{
	return pack_TPM2B_DIGEST(ptr, data);
}

inline BYTE* pack_TPM2B_PUBLIC_KEY_RSA(BYTE* ptr, const TPM2B_NONCE *rsa)
{
	return pack_TPM2B_DIGEST(ptr, rsa);
}

inline BYTE* pack_TPM_AuthArea(BYTE* ptr, const TPM_AuthArea *auth)
{
	ptr += pack_TPM_HANDLE(ptr, auth->authHandle);
	ptr += pack_TPM2B_NONCE(ptr, &auth->nonceCaller);
	ptr += pack_TPMA_SESSION(ptr, auth->sessionAttribute);
	ptr += pack_TPM2B_AUTH(ptr, &auth->hmac);
	return ptr;
}

inline BYTE* pack_TPMS_SENSITIVE_CREATE(BYTE* ptr, const TPMS_SENSITIVE_CREATE *create)
{
	ptr += pack_TPM2B_AUTH(ptr, &create->userAuth);
	ptr += pack_TPM2B_SENSITIVE_DATA(ptr, &create->data);
	return ptr;
}

inline BYTE* pack_TPM2B_SENSITIVE_CREATE(BYTE* ptr, const TPM2B_SENSITIVE_CREATE *create)
{
	BYTE* sizePtr = ptr;
	ptr += 2;
	ptr = pack_TPMS_SENSITIVE_CREATE(ptr, &create->sensitive);
	pack_UINT16(sizePtr, (UINT16)(ptr - sizePtr - 2));
	return ptr;
}

inline BYTE* pack_TPMU_PUBLIC_PARAMS(BYTE* ptr, const TPMU_PUBLIC_PARAMS *param, const TPMI_ALG_PUBLIC selector)
{
	switch(selector) {
		case TPM_ALG_KEYEDHASH:
			return pack_TPMS_KEYEDHASH_PARAMS(ptr, &params->keyedHashDetail);
		case TPM_ALG_SYMCIPHER:
			return pack_TPMS_SYMCIPHER_PARAMS(ptr, &params->symDetail);
		case TPMS_RSA_PARAMS:
			return pack_TPMS_RSA_PARAMS(ptr, &params->rsaDetail);
		case TPMS_ECC_PARAMS:
			return pack_TPMS_ECC_PARAMS(ptr, &params->eccDetail);
	}
	assert(false);
	return NULL;
}

inline BYTE* pack_TPMS_ECC_POINT(BYTE* ptr, const TPMS_ECC_POINT *point)
{
	assert(false);
	return ptr;
}

inline BYTE* pack_TPMU_PUBLIC_ID(BYTE* ptr, const TPMU_PUBLIC_ID *id, const TPMI_ALG_PUBLIC selector)
{
	switch (selector) {
		case TPM_ALG_KEYEDHASH:
			return pack_TPM2B_DIGEST(ptr, &id->keyedHash);
		case TPM_ALG_SYMCIPHER:
			return pack_TPM2B_DIGEST(ptr, &id->sym);
		case TPM_ALG_RSA:
			return pack_TPM2B_PUBLIC_KEY_RSA(ptr, &id->rsa);
		case TPM_ALG_ECC:
			return pack_TPMS_ECC_POINT(ptr, &id->ecc);
	}
	assert(false);
	return NULL;
}

inline BYTE* pack_TPMT_PUBLIC(BYTE* ptr, const TPMT_PUBLIC *public)
{
	ptr = pack_TPMI_ALG_PUBLIC(ptr, public->type);
	ptr = pack_TPMI_ALG_HASH(ptr, public->nameAlg);
	ptr = pack_TPMA_OBJECT(ptr, public->objectAttributes);
	ptr = pack_TPM2B_DIGEST(ptr, &public->authPolicy);
	ptr = pack_TPMU_PUBLIC_PARAMS(ptr, &public->parameters, public->type);
	ptr = pack_TPMU_PUBLIC_ID(ptr, &public->unique, public->type);
	return ptr;
}

inline BYTE* pack_TPM2B_PUBLIC(BYTE* ptr, const TPM2B_PUBLIC *public)
{
	BYTE *sizePtr = ptr;
	ptr += 2;
	ptr = pack_TPMT_PUBLIC(ptr, public->publicArea);
	pack_UINT16(sizePtr, (UINT16)(ptr - sizePtr - 2));
	return ptr;
}


inline BYTE* pack_TPMS_PCR_SELECTION(BYTE* ptr, const TPMS_PCR_SELECTION *selection)
{
	ptr = pack_TPMI_ALG_HASH(ptr, &selection->hash);
	ptr = pack_BYTE(ptr, selection->sizeofSelect);
	ptr = pack_BYTE_Array(ptr, selection->pcrSelect, selection->sizeofSelect);
	return ptr;
}

inline BYTE* pack_TPMS_PCR_SELECTION_Array(BYTE* ptr, const TPMS_PCR_SELECTION *selections, const UINT32 cnt)
{
	int i;
	for (i = 0; i < cnt; i++)
		ptr = pack_TPMS_PCR_SELECTION(ptr, selections + i);
	return ptr;
}

inline BYTE* pack_TPML_PCR_SELECTION(BYTE* ptr, const TPML_PCR_SELECTION *selection)
{
	ptr = pack_UINT32(ptr, selection->count);
	ptr = pack_TPMS_PCR_SELECTION_Array(ptr, selection->pcrSelections, selection->count);
	return ptr;
}
