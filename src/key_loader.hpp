#pragma once
// Loads .NET RSAKeyValue XML keys (as produced by
// RSACryptoServiceProvider.ToXmlString()).
//
// Private: <RSAKeyValue><Modulus><Exponent><P><Q><DP><DQ><InverseQ><D> (base64)
// Public: <RSAKeyValue><Modulus><Exponent></RSAKeyValue>
//
// Returns openssl::Key (the RAII wrapper around EVP_PKEY): all crypto goes
// through the openssl.hpp EVP_PKEY layer; RSA* assembly details stay inside
// openssl.cpp. This file only parses XML and decodes base64.

#include <string>

#include "openssl.hpp"

// Loads an RSA private key from a .NET RSAKeyValue XML file; throws
// std::runtime_error on failure (missing file / missing <Modulus>/<Exponent>
// / missing private parameter <D>)
[[nodiscard]] openssl::Key loadPrivateEvpKeyFromXml(const std::string& xmlPath);

// Loads an RSA public key from a .NET RSAKeyValue XML file; throws
// std::runtime_error on failure (even if the XML carries private parameters,
// only <Modulus>/<Exponent> are used - never yields the private key)
[[nodiscard]] openssl::Key loadPublicEvpKeyFromXml(const std::string& xmlPath);
