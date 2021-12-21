#include <KeyPairGenerator.h>

#define KEY_SIZE 2048
#define EXPONENT 65537

mbedtls_pk_context pk;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;

bool KeyPairGenerator::generateKeyPair(char* publicKeyFilePath, char* privateKeyFilePath,
  void (*f_MySerialInfo)(const char* szformat, ...)){

  int ret;
  bool success = false;

  const char *pers = "rsa_genkey";

  mbedtls_ctr_drbg_init( &ctr_drbg );

  mbedtls_pk_init( &pk );
  mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
  mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
  mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

  this->MySerial( "\n  . Seeding the random number generator..." );
  mbedtls_entropy_init( &entropy );
  if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 ){
    this->MySerial( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
    cleanup();
    return false;
  }

  if((ret = mbedtls_pk_setup( &pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA) )) != 0){
    this->MySerial("pk_setup failed: %i\n", ret);
  }

  this->MySerial( " ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE );
  if( ( ret = mbedtls_rsa_gen_key( mbedtls_pk_rsa( pk ), mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, EXPONENT ) ) != 0 ){
    this->MySerial( " failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret );
    cleanup();
    return false;
  }

  this->MySerial( " ok\n  . Checking public/private key validity...");
  if(mbedtls_rsa_check_pubkey(mbedtls_pk_rsa( pk ))!=0){
    this->MySerial("RSA context does not contain an rsa public key");
    cleanup();
    return false;
  }
  if(mbedtls_rsa_check_privkey(mbedtls_pk_rsa( pk ))!=0){
    this->MySerial("RSA context does not contain an rsa private key");
    cleanup();
    return false;
  }

  this->MySerial( " ok\n  . Writing public key to string(PEM format)...." );

  unsigned char pubKeyPem[1000];
  memset(pubKeyPem, 0, sizeof(pubKeyPem));
  if(mbedtls_pk_write_pubkey_pem(&pk, pubKeyPem, sizeof(pubKeyPem)) != 0){
    this->MySerial("write public key to string failed");
    cleanup();
    return false;
  }
  // ORIGINAL Serial.printf("Public Key:\n%s\n", (char*)pubKeyPem);
  this->MySerial( " ok\n  . Writing private key to string(PEM format)...." );

  unsigned char privKeyPem[2000];
  memset(privKeyPem, 0, sizeof(privKeyPem));
  ret = mbedtls_pk_write_key_pem(&pk, privKeyPem, sizeof(privKeyPem));
  if(ret!=0){
    this->MySerial("write private key to string failed with code %04x\n",ret);
  }
  // ORIGINAL Serial.printf("Private Key:\n%s\n",(char*)privKeyPem);
  this->MySerial( " ok\n  . Storing keys to SPIFFS...." );

  File publicKeyFile;
  publicKeyFile = SPIFFS.open(publicKeyFilePath, FILE_WRITE);
  if(publicKeyFile){
    publicKeyFile.print((char*)pubKeyPem);
  }else{
    this->MySerial("Could not locate public key file at given path");
    cleanup();
    return false;
  }

  File privateKeyFile;
  privateKeyFile = SPIFFS.open(privateKeyFilePath, FILE_WRITE);
  if(privateKeyFile){
    privateKeyFile.print((char*)privKeyPem);
  }else{
    this->MySerial("Could not locate private key file at given path");
    cleanup();
    return false;
  }

  this->MySerial("Success, process complete");
  cleanup();
  return true;
}

void KeyPairGenerator::cleanup(){
  mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
  mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
  mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free( &entropy );
}

void KeyPairGenerator::MySerial(const char* szformat, ...)
{
  //
  if (!m_bSerial) return;

  //
  va_list argptr;
  va_start(argptr, szformat);
  vfprintf(stderr, szformat, argptr);
  va_end(argptr);

  //
  if (this->m_funcMySerialInfo != nullptr) this->m_funcMySerialInfo(szformat);
  else Serial.println(szformat);
}