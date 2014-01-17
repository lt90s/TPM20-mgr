
static TPM_RC TPM2_Create(TPMI_DH_OBJECT parentHandle, \
								TPM2_Create_Params_in *in \
								TPM2_Create_Params_out *out)
{
	UINT32 param_size;
	TPM_BEGIN(TPM_ST_SESSIONS, TPM_CC_Create);
	
	/* pack handle of parent for new object */
	ptr =  pack_UINT32(ptr, parentHandle);
	
	/* pack Auth Area */
	ptr = pack_TPM_AuthArea(ptr, &vtpm_globals.pwAuth);

	/* pack inSensitive */
	ptr = pack_TPM2B_SENSITIVE_CREATE(ptr, &in->inSensitive);

	/* pack inPublic */
	ptr = pack_TPM2B_PUBLIC(ptr, &in->inPublic);

	/* pack outside Info */
	ptr = pack_TPM2B_DATA(ptr, &in->outsideInfo);

	/* pack createPCR */
	ptr = pack_TPML_PCR_SELECTION(ptr, &in->creationPCR);
	
	/* Send the command to the tpm */
	TPM_TRANSMIT();

	/* Unpack and validate the header */
	TPM_UNPACK_VERIFY();
	
	ptr = unpack_UINT32(ptr, &param_size);

	if (out != NULL) {
		ptr = unpack_TPM2B_PUBLIC(ptr, &out->outPublic);
	
		ptr = unpack_TPM2B_CREATION_DATA(ptr, &out->creationData);

		ptr = unpack_TPM2B_DIGEST(ptr, &out->creationHash);

		ptr = unpack_TPMT_TK_CREATION(ptr, &out->creationTicket);

		ptr = unpack_TPM2B_NAME(ptr, &out->name);
	} else
		ptr += param_size;

	ptr = unpack_TPM2_AuthArea(ptr, &vtpm_globals.pwAuth);
	
	goto egress;

abort_egress:

egress:
	return status;
}

static TPM_RC TPM2_CreatePrimary(TPMI_RH_HIERARCHY primaryHandle, \
										TPM2_Create_Params_in *in, \
											TPM_HANDLE *objHandle, \
											TPM2_Create_Params_out *out)
{
	UINT32 param_size;
	TPM_BEGIN(TPM_ST_SESSIONS, TPM_CC_CreatePrimary);

	/* pack primary handle */
	ptr = pack_UINT32(ptr, primaryHandle);
	
	/* pack Auth Area */
	ptr = pack_TPM_AuthArea(ptr, &vtpm_globals.pwAuth);

	/* pack inSenstive */
	ptr = pack_TPM2B_SENSITIVE_CREATE(ptr, in->inSensitive);

	/* pack inPublic */
	ptr = pack_TPM2B_PUBLIC(ptr, &in->inPublic);

	/* pack outsideInfo */
	ptr = pack_TPM2B_DATA(ptr, &in->outsideInfo);

	/* pack creationPCR */
	ptr = pack_TPML_PCR_SELECTION(ptr, &in->creationPCR);

	/* Send the command to the tpm */
	TPM_TRANSMIT();

	/* Unpack and validate the header */
	TPM_UNPACK_VERIFY();

	if (objHandle != NULL)
		ptr = unpack_TPM_HANDLE(ptr, objHandle);
	else {
		TPM2_HANDLE handle;
		ptr = unpack_TPM_HANDLE(ptr, &handle);
	}
	
	ptr = unpack_UINT32(ptr, &param_size);

	if (out != NULL) {
		ptr = unpack_TPM2B_PUBLIC(ptr, &out->outPublic);
	
		ptr = unpack_TPM2B_CREATION_DATA(ptr, &out->creationData);

		ptr = unpack_TPM2B_DIGEST(ptr, &out->creationHash);

		ptr = unpack_TPMT_TK_CREATION(ptr, &out->creationTicket);

		ptr = unpack_TPM2B_NAME(ptr, &out->name);
	} else
		ptr += param_size;

	ptr = unpack_TPM2_AuthArea(ptr, &vtpm_globals.pwAuth);
	goto egress;

abort_egress:

egress:
	return status;
}
static TPM_RC TPM2_HierachyChangeAuth(TPMI_RH_HIERACHY_AUTH authHandle, TPM2B_AUTH *newAuth)
{
	TPM_BEGIN(TPM_ST_SESSIONS, TPM_CC_HierachyChangeAuth);
	ptr = pack_UINT32(ptr, authHandle);
	ptr = pack_TPM_AuthArea(ptr, &vtpm_globals.pwAuth);
	ptr = pack_TPM2B_AUTH(ptr, newAuth);
	TPM_TRANSMIT();

	TPM_UNPACK_VERIFY();

abort_egress:
	return status;
}

static TPM_RC try_take_ownership(void)
{
	TPM_RC status = TPM_SUCCESS;

	/* insert ownerAuth, endorsementAuth and lockoutAuth */
	TPMTRYRETURN(TPM2_HierachyChangeAuth(TPM_RH_OWNER, &vtpm_globals.TPM2_ownerAuth));

	TPMTRYRETURN(TPM2_HierachyChangeAuth(TPM_RH_ENDORSEMENT, &vtpm_globals.TPM2_endorsementAuth));

	TPMTRYRETURN(TPM2_HierachyChangeAuth(TPM_RH_LOCKOUT, &vtpm_globals.TPM2_lockoutAuth));
	
	/* create SRK */
	{
		/* size will be correctly set when marshaled into cmd buffer */
		TPM2_CreatePrimary_Params_in in = {
			.inSensitive = {
				.size = cpu_to_be32(0);
				.sensitive = {
					.userAuth.size = cpu_to_be16(SHA1_DIGEST_SIZE);
					/* .userAuth.buffer[] */

					/* this means senstiveDataOrigin must be set */
					.data.size = cpu_to_be16(0);
				},
			},
			.inPublic = {
				.size = cpu_to_be16(0),
				.publicArea = {
					.type = TPM_ALG_RSA,
					.nameAlg = TPM_ALG_SHA1,
#define SRK_OBJ_ATTR cpu_to_be32(fixedTPM | fixedParent | userWithAuth \
									sensitiveDataOrigin | restricted | decrypt)
					.objectAttribute = SRK_OBJ_ATTR,
					.authPolicy.size = 0,
					.params.rsaDetail = {
						.symmetric = {
							.algorithm = TPM_ALG_AES,
							.keyBits.aes = AES_KEY_SIZES_BITs,
							.mode.aes = TPM2_ALG_CFB,
						},
						.sheme = TPM_ALG_NULL,
						.keyBits = RSA_KEY_SIZES_BITS,
						.exponet = 0,
					},
					.unique.rsa.size = 0,
				},
			},
			.outsideInfo.size = 0,
			creationPCR.count = 0,
		};
		TPMTRYRETURN(TPM2_CreatePrimary(TPM_RH_OWNER, &in, &vtpm_globals.srk_handle, NULL /* how does it can be used ? */));
	}
abort_egree:
	return status;
}
