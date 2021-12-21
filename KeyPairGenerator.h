#ifndef KEYPAIRGENERATOR_H
#define KEYPAIRGENERATOR_H

#include <Arduino.h>
#include <SPIFFS.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/rsa.h"
#include "mbedtls/config.h"
#include "mbedtls/platform.h"

class KeyPairGenerator{
public:
  //Generate and store a private/public key pair RSA 2048 bit
  bool generateKeyPair(char* publicKeyFilePath, char* privateKeyFilePath);

  //
  void SetSerial(bool b) { m_bSerial = b; }
  void MySerial(const char* szformat, ...);
  void SetMyFuncSerialInfo(void(*f)(const char* szformat, ...)) { m_funcMySerialInfo = f; }

  //
  void (*m_funcMySerialInfo)(const char* szformat, ...) = nullptr;

private:
  void cleanup();

  //
  bool m_bSerial = false;
};
#endif
