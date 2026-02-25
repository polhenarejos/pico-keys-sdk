#
# OpenSSL  wrapper configuration for Pico Keys SDK.
# Keeps OpenSSL-specific build logic out of pico_keys_sdk_import.cmake.
#

if(NOT DEFINED USE_OPENSSL)
    set(USE_OPENSSL 0)
endif()

set(SKIP_MBEDTLS_FOR_OPENSSL_EMULATION 0)
set(USE_OPENSSL_EMULATION_WRAPPER 0)

if(ENABLE_EMULATION AND USE_OPENSSL)
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        set(SKIP_MBEDTLS_FOR_OPENSSL_EMULATION 1)
        set(USE_OPENSSL_EMULATION_WRAPPER 1)
        message(STATUS "OpenSSL backend:\t\t enabled")
    else()
        message(STATUS "OpenSSL backend:\t\t disabled (OpenSSL not found)")
    endif()
elseif(ENABLE_EMULATION)
    message(STATUS "OpenSSL backend:\t\t disabled")
endif()

if(USE_OPENSSL_EMULATION_WRAPPER)
    add_definitions(
        -Dmbedtls_platform_zeroize=openssl_mbedtls_platform_zeroize
        -Dmbedtls_sha256=openssl_mbedtls_sha256
        -Dmbedtls_sha256_init=openssl_mbedtls_sha256_init
        -Dmbedtls_sha256_free=openssl_mbedtls_sha256_free
        -Dmbedtls_sha256_starts=openssl_mbedtls_sha256_starts
        -Dmbedtls_sha256_update=openssl_mbedtls_sha256_update
        -Dmbedtls_sha256_finish=openssl_mbedtls_sha256_finish
        -Dmbedtls_md_info_from_type=openssl_mbedtls_md_info_from_type
        -Dmbedtls_md_get_size=openssl_mbedtls_md_get_size
        -Dmbedtls_md=openssl_mbedtls_md
        -Dmbedtls_md_hmac=openssl_mbedtls_md_hmac
        -Dmbedtls_md_init=openssl_mbedtls_md_init
        -Dmbedtls_md_free=openssl_mbedtls_md_free
        -Dmbedtls_md_setup=openssl_mbedtls_md_setup
        -Dmbedtls_md_starts=openssl_mbedtls_md_starts
        -Dmbedtls_md_update=openssl_mbedtls_md_update
        -Dmbedtls_md_finish=openssl_mbedtls_md_finish
        -Dmbedtls_hkdf=openssl_mbedtls_hkdf
        -Dmbedtls_aes_init=openssl_mbedtls_aes_init
        -Dmbedtls_aes_free=openssl_mbedtls_aes_free
        -Dmbedtls_aes_setkey_enc=openssl_mbedtls_aes_setkey_enc
        -Dmbedtls_aes_setkey_dec=openssl_mbedtls_aes_setkey_dec
        -Dmbedtls_aes_crypt_ecb=openssl_mbedtls_aes_crypt_ecb
        -Dmbedtls_aes_crypt_cbc=openssl_mbedtls_aes_crypt_cbc
        -Dmbedtls_aes_crypt_cfb128=openssl_mbedtls_aes_crypt_cfb128
        -Dmbedtls_aes_crypt_ofb=openssl_mbedtls_aes_crypt_ofb
        -Dmbedtls_aes_crypt_ctr=openssl_mbedtls_aes_crypt_ctr
        -Dmbedtls_aes_xts_init=openssl_mbedtls_aes_xts_init
        -Dmbedtls_aes_xts_free=openssl_mbedtls_aes_xts_free
        -Dmbedtls_aes_xts_setkey_enc=openssl_mbedtls_aes_xts_setkey_enc
        -Dmbedtls_aes_xts_setkey_dec=openssl_mbedtls_aes_xts_setkey_dec
        -Dmbedtls_aes_crypt_xts=openssl_mbedtls_aes_crypt_xts
        -Dmbedtls_gcm_init=openssl_mbedtls_gcm_init
        -Dmbedtls_gcm_free=openssl_mbedtls_gcm_free
        -Dmbedtls_gcm_setkey=openssl_mbedtls_gcm_setkey
        -Dmbedtls_gcm_crypt_and_tag=openssl_mbedtls_gcm_crypt_and_tag
        -Dmbedtls_gcm_auth_decrypt=openssl_mbedtls_gcm_auth_decrypt
        -Dmbedtls_ccm_init=openssl_mbedtls_ccm_init
        -Dmbedtls_ccm_free=openssl_mbedtls_ccm_free
        -Dmbedtls_ccm_setkey=openssl_mbedtls_ccm_setkey
        -Dmbedtls_ccm_encrypt_and_tag=openssl_mbedtls_ccm_encrypt_and_tag
        -Dmbedtls_ccm_auth_decrypt=openssl_mbedtls_ccm_auth_decrypt
        -Dmbedtls_chachapoly_init=openssl_mbedtls_chachapoly_init
        -Dmbedtls_chachapoly_free=openssl_mbedtls_chachapoly_free
        -Dmbedtls_chachapoly_setkey=openssl_mbedtls_chachapoly_setkey
        -Dmbedtls_chachapoly_encrypt_and_tag=openssl_mbedtls_chachapoly_encrypt_and_tag
        -Dmbedtls_chachapoly_auth_decrypt=openssl_mbedtls_chachapoly_auth_decrypt
        -Dmbedtls_cipher_info_from_type=openssl_mbedtls_cipher_info_from_type
        -Dmbedtls_cipher_cmac=openssl_mbedtls_cipher_cmac
        -Dmbedtls_mpi_init=openssl_mbedtls_mpi_init
        -Dmbedtls_mpi_free=openssl_mbedtls_mpi_free
        -Dmbedtls_mpi_grow=openssl_mbedtls_mpi_grow
        -Dmbedtls_mpi_lset=openssl_mbedtls_mpi_lset
        -Dmbedtls_mpi_size=openssl_mbedtls_mpi_size
        -Dmbedtls_mpi_read_binary=openssl_mbedtls_mpi_read_binary
        -Dmbedtls_mpi_read_binary_le=openssl_mbedtls_mpi_read_binary_le
        -Dmbedtls_mpi_write_binary=openssl_mbedtls_mpi_write_binary
        -Dmbedtls_mpi_write_binary_le=openssl_mbedtls_mpi_write_binary_le
        -Dmbedtls_mpi_copy=openssl_mbedtls_mpi_copy
        -Dmbedtls_mpi_cmp_mpi=openssl_mbedtls_mpi_cmp_mpi
        -Dmbedtls_mpi_cmp_int=openssl_mbedtls_mpi_cmp_int
        -Dmbedtls_mpi_add_mpi=openssl_mbedtls_mpi_add_mpi
        -Dmbedtls_mpi_add_int=openssl_mbedtls_mpi_add_int
        -Dmbedtls_mpi_sub_abs=openssl_mbedtls_mpi_sub_abs
        -Dmbedtls_mpi_mod_mpi=openssl_mbedtls_mpi_mod_mpi
        -Dmbedtls_asn1_get_tag=openssl_mbedtls_asn1_get_tag
        -Dmbedtls_asn1_get_int=openssl_mbedtls_asn1_get_int
        -Dmbedtls_asn1_get_alg_null=openssl_mbedtls_asn1_get_alg_null
        -Dmbedtls_oid_get_md_hmac=openssl_mbedtls_oid_get_md_hmac
        -Dmbedtls_pkcs5_pbkdf2_hmac_ext=openssl_mbedtls_pkcs5_pbkdf2_hmac_ext
        -Dmbedtls_pkcs5_pbes2_ext=openssl_mbedtls_pkcs5_pbes2_ext
        -Dmbedtls_rsa_gen_key=openssl_mbedtls_rsa_gen_key
        -Dmbedtls_rsa_init=openssl_mbedtls_rsa_init
        -Dmbedtls_rsa_free=openssl_mbedtls_rsa_free
        -Dmbedtls_rsa_set_padding=openssl_mbedtls_rsa_set_padding
        -Dmbedtls_rsa_get_len=openssl_mbedtls_rsa_get_len
        -Dmbedtls_rsa_import=openssl_mbedtls_rsa_import
        -Dmbedtls_rsa_complete=openssl_mbedtls_rsa_complete
        -Dmbedtls_rsa_check_pubkey=openssl_mbedtls_rsa_check_pubkey
        -Dmbedtls_rsa_check_privkey=openssl_mbedtls_rsa_check_privkey
        -Dmbedtls_ecp_curve_info_from_grp_id=openssl_mbedtls_ecp_curve_info_from_grp_id
        -Dmbedtls_ecp_get_type=openssl_mbedtls_ecp_get_type
        -Dmbedtls_ecp_group_init=openssl_mbedtls_ecp_group_init
        -Dmbedtls_ecp_group_free=openssl_mbedtls_ecp_group_free
        -Dmbedtls_ecp_group_load=openssl_mbedtls_ecp_group_load
        -Dmbedtls_ecp_keypair_init=openssl_mbedtls_ecp_keypair_init
        -Dmbedtls_ecp_keypair_free=openssl_mbedtls_ecp_keypair_free
        -Dmbedtls_ecp_gen_key=openssl_mbedtls_ecp_gen_key
        -Dmbedtls_ecp_mul=openssl_mbedtls_ecp_mul
        -Dmbedtls_ecp_read_key=openssl_mbedtls_ecp_read_key
        -Dmbedtls_ecp_write_key_ext=openssl_mbedtls_ecp_write_key_ext
        -Dmbedtls_ecp_point_read_binary=openssl_mbedtls_ecp_point_read_binary
        -Dmbedtls_ecp_point_write_binary=openssl_mbedtls_ecp_point_write_binary
        -Dmbedtls_ecp_point_edwards=openssl_mbedtls_ecp_point_edwards
        -Dmbedtls_ecp_check_pubkey=openssl_mbedtls_ecp_check_pubkey
        -Dmbedtls_ecp_check_pub_priv=openssl_mbedtls_ecp_check_pub_priv
        -Dmbedtls_ecdsa_init=openssl_mbedtls_ecdsa_init
        -Dmbedtls_ecdsa_free=openssl_mbedtls_ecdsa_free
        -Dmbedtls_ecdsa_genkey=openssl_mbedtls_ecdsa_genkey
        -Dmbedtls_rsa_private=openssl_mbedtls_rsa_private
        -Dmbedtls_rsa_pkcs1_sign=openssl_mbedtls_rsa_pkcs1_sign
        -Dmbedtls_rsa_rsassa_pkcs1_v15_sign=openssl_mbedtls_rsa_rsassa_pkcs1_v15_sign
        -Dmbedtls_rsa_pkcs1_verify=openssl_mbedtls_rsa_pkcs1_verify
        -Dmbedtls_rsa_pkcs1_decrypt=openssl_mbedtls_rsa_pkcs1_decrypt
        -Dmbedtls_ecdh_init=openssl_mbedtls_ecdh_init
        -Dmbedtls_ecdh_free=openssl_mbedtls_ecdh_free
        -Dmbedtls_ecdh_setup=openssl_mbedtls_ecdh_setup
        -Dmbedtls_ecdh_gen_public=openssl_mbedtls_ecdh_gen_public
        -Dmbedtls_ecdh_read_public=openssl_mbedtls_ecdh_read_public
        -Dmbedtls_ecdh_calc_secret=openssl_mbedtls_ecdh_calc_secret
        -Dmbedtls_ecdsa_sign=openssl_mbedtls_ecdsa_sign
        -Dmbedtls_ecdsa_verify=openssl_mbedtls_ecdsa_verify
        -Dmbedtls_ecdsa_write_signature=openssl_mbedtls_ecdsa_write_signature
        -Dmbedtls_eddsa_sign=openssl_mbedtls_eddsa_sign
        -Dmbedtls_eddsa_write_signature=openssl_mbedtls_eddsa_write_signature
    )
endif()
