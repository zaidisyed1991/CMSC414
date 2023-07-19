// gcc -g -O0 -Wall foo.c -o foo -lssl -lcrypto 
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>


int encrypt(FILE *plaintext_f, FILE *ciphertext_f, const char *pubkey_filename);
int decrypt(FILE *plaintext_f, FILE *ciphertext_f, const char *pkey_filename);
EVP_PKEY *load_privkey(const char *file);
EVP_PKEY *load_pubkey(const char *file);

int main(int argc, char *argv[])
{
    if (argc != 4) {
        return 2;
    }

    int ret;
    if (argv[1][0] == 'e') {
        FILE *plaintext = fopen(argv[3], "rb");
        if (!plaintext) 
            return 2;
        if((ret = encrypt(plaintext, stdout, argv[2])))
            return ret;
        fclose(plaintext);
    } else if (argv[1][0] == 'd') {
        FILE *ciphertext = fopen(argv[3], "rb");
        if(!ciphertext)
            return 2;
        if((ret = decrypt(ciphertext, stdout, argv[2])))
            return ret;
        fclose(ciphertext);
    } else {
        printf("geeee");
        return 2;
    }
    return 0;
}

int encrypt(FILE *plaintext_f, FILE *ciphertext_f, const char* pubkey_filename)
{
	int ret = 0, len_out, encrypted_key_length;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_PKEY *pkey;
	unsigned char iv[EVP_MAX_IV_LENGTH], *encrypted_key, buffer[4096], buffer_out[4096 + EVP_MAX_IV_LENGTH];
	size_t len;
	uint32_t eklen_n;

	pkey = load_pubkey(pubkey_filename);
	encrypted_key = malloc(EVP_PKEY_size(pkey));
	encrypted_key_length = EVP_PKEY_size(pkey);
	if (!EVP_SealInit(ctx, EVP_des_ede_cbc(), &encrypted_key, &encrypted_key_length, iv, &pkey, 1))
	{
		ret = 2;
		goto end;
	}
	eklen_n = htonl(encrypted_key_length);
	if (fwrite(&eklen_n, sizeof(eklen_n), 1, ciphertext_f) != 1)
	{
		ret = 2;
		goto end;
	}
	if (fwrite(encrypted_key, encrypted_key_length, 1, ciphertext_f) != 1)
	{
		ret = 2;
		goto end;
	}
	if (fwrite(iv, EVP_CIPHER_iv_length(EVP_des_ede_cbc()), 1, ciphertext_f) != 1)
	{
		ret = 2;
		goto end;
	}
	while ((len = fread(buffer, 1, sizeof(buffer), plaintext_f)) > 0)
	{
		if (!EVP_SealUpdate(ctx, buffer_out, &len_out, buffer, len))
		{
			ret = 2;
			goto end;
		}

		if (fwrite(buffer_out, len_out, 1, ciphertext_f) != 1)
		{
			ret = 2;
			goto end;
		}
	}
	if (!EVP_SealFinal(ctx, buffer_out, &len_out))
	{
		ret = 2;
		goto end;
	}
	if (fwrite(buffer_out, len_out, 1, ciphertext_f) != 1)
	{
		ret = 2;
		goto end;
	}

    end:
	EVP_PKEY_free(pkey);
	free(encrypted_key);
	EVP_CIPHER_CTX_cleanup(ctx);
	return ret;
}


int decrypt(FILE *plaintext_f, FILE *ciphertext_f, const char *pkey_filename)
{
	int ret = 0, len_out;
	unsigned char buffer[4096], buffer_out[4096 + EVP_MAX_IV_LENGTH], *encrypted_key, iv[EVP_MAX_IV_LENGTH];
	size_t len;
	unsigned int encrypted_key_length;
	uint32_t eklen_n;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_PKEY *pkey = load_privkey(pkey_filename);
	encrypted_key = malloc(EVP_PKEY_size(pkey));

	if (fread(&eklen_n, sizeof(eklen_n), 1, plaintext_f) != 1)
	{
		ret = 2;
		goto end;
	}

	encrypted_key_length = ntohl(eklen_n);
	if (encrypted_key_length > EVP_PKEY_size(pkey))
	{
		ret = 2;
		goto end;
	}
	if (fread(encrypted_key, encrypted_key_length, 1, plaintext_f) != 1)
	{
		ret = 2;
		goto end;
	}
	if (fread(iv, EVP_CIPHER_iv_length(EVP_des_ede_cbc()), 1, plaintext_f) != 1)
	{
		ret = 2;
		goto end;
	}

	if (!EVP_OpenInit(ctx, EVP_des_ede_cbc(), encrypted_key, encrypted_key_length, iv, pkey))
	{
		ret = 2;
		goto end;
	}

	while ((len = fread(buffer, 1, sizeof(buffer), plaintext_f)) > 0)
	{
		if (!EVP_OpenUpdate(ctx, buffer_out, &len_out, buffer, len))
		{
			ret = 2;
			goto end;
		}

		if (fwrite(buffer_out, len_out, 1, ciphertext_f) != 1)
		{
			ret = 2;
			goto end;
		}
	}

	if (!EVP_OpenFinal(ctx, buffer_out + len_out, &len_out))
	{
		fprintf(stderr, "EVP_OpenFinal: failed.\n");
		ret = 2;
		goto end;
	}

	if (fwrite(buffer_out, len_out, 1, ciphertext_f) != 1)
	{
		ret = 2;
		goto end;
	}

    end:
	EVP_PKEY_free(pkey);
	free(encrypted_key);
	EVP_CIPHER_CTX_cleanup(ctx);
	return ret;
}


EVP_PKEY *load_privkey(const char *file)
{

	RSA *rsa_pkey = NULL;
	BIO *rsa_pkey_file = NULL;
	EVP_PKEY *pkey = EVP_PKEY_new();

	rsa_pkey_file = BIO_new(BIO_s_file());
	if (rsa_pkey_file == NULL)
		goto end;
	if (BIO_read_filename(rsa_pkey_file, file) <= 0)
		goto end;
	if (!PEM_read_bio_RSAPrivateKey(rsa_pkey_file, &rsa_pkey, NULL, NULL))
		goto end;
    if (!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
        goto end;

end:
	if (rsa_pkey_file != NULL)
		BIO_free(rsa_pkey_file);
	return(pkey);
}

EVP_PKEY *load_pubkey(const char *file)
{

	RSA *rsa_pkey = NULL;
	BIO *rsa_pkey_file = NULL;
	EVP_PKEY *pkey = EVP_PKEY_new();

	rsa_pkey_file = BIO_new(BIO_s_file());
	if (rsa_pkey_file == NULL)
		goto end;
	
	if (BIO_read_filename(rsa_pkey_file, file) <= 0)
		goto end;

	if (!PEM_read_bio_RSA_PUBKEY(rsa_pkey_file, &rsa_pkey, NULL, NULL))
		goto end;

    if (!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
        goto end;

    end:
	if (rsa_pkey_file != NULL)
		BIO_free(rsa_pkey_file);
	return(pkey);
}