# Common R2PS service types

This document defines common service types exchanged under the R2PS protocol.

## 1 HSM EC key generation request

### 1.1 Type identifier

The EC HSM key generation service type is identified by the following type identifier:

> hsm_ec_keygen

### 1.2. Service type data

This service type generates an EC key for a requested EC curve in the remote HSM, if the request is accepted. If the request is denied, an error response is returned.

The service request data includes an encrypted JWE where the payload holds a JSON object with the following parameters: 

- `curve` : (**string**) - A registered name of the requested EC curve

The service response 

data includes an encrypted JWE where the payload holds a JSON object with the following parameters:

- `created_key` : (**string**) - A registered name of the requested EC curve for which a key is created

### 1.3 Example

Create EC key - service request

```json
{
"ver" : "1.0",
"nonce" : "ce1236513eff5bbbc67a24681b236f68dbd414b330ab5320cab9e4c24225dcc3",
"iat" : 1750750250,
"enc" : "user",
"data" : "ZXlKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWVd4bklqb2laR2x5SW4wLi5ScjIza0JyZkpUSVFnWjcxLnVBazlMdmwybHBpZVp0eENoaXBiTzhrLmpsQjN6bE5NcXNzdDhiYjBxMXdLamc=",
"client_id" : "https://example.com/wallet/1",
"kid" : "Ar2IGiWEJnjb57P2V4hLQIaDZuzmt54bN227obY5NSIL",
"context" : "hsm",
"type" : "hsm_ec_keygen",
"pake_session_id" : "edd1e0eb4c20debf6b3cc3ee84d53d5d419f37206c3c60131d0386f9763e41b0"
}
```

Decrypted JWE payload

```json
{
"curve" : "P-256"
}
```

Create EC key - service response
```json
{
"ver" : "1.0",
"nonce" : "ce1236513eff5bbbc67a24681b236f68dbd414b330ab5320cab9e4c24225dcc3",
"iat" : 1750750250,
"enc" : "user",
"data" : "ZXlKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWVd4bklqb2laR2x5SW4wLi5CYlFwYmlCSTNVVl9Tb1JQLkN3TEdXN0lzU1Qxd0Mzb255QncyYUd6NWpqM2NNV0EuZDQ0V2dXRWZNeWtGOFZCVzl5Vm1fdw=="
}
```

Decrypted JWE payload
```json
{
"created_key" : "P-256"
}
```


## 2 List HSM keys

### 2.1 Type identifier

The list HSM keys service type is identified by the following type identifier:

> hsm_list_keys

### 2.2 Service type data

This service type requests a list of EC keys for specified EC curves that are available in the remote HSM.

The service request data includes an encrypted JWE where the payload holds a JSON object with the following parameters:

- `curve` : (**string array**) - An array of registered EC curve names for which key information is requested. Absent or empty list indicates that all keys should be listed.

The service response data includes an encrypted JWE where the payload holds a JSON object with the following parameters:

- `key_info` : (**object array**) - An array of key_info data for each available key.

each `key_info` object includes the following parameters:

- `kid` : (**string**) - The key identifier used to request operations with this key
- `curve_name` : (**string**) - The name of the EC curve specified when requesting this key
- `creation_time` : (**integer**) - Seconds since epoch when this key was created
- `public_key` : (**byte array**) - The compressed point byte array of the public key

### 2.3 Example

List HSM keys - service request

```json
{
"ver" : "1.0",
"nonce" : "8e85a3cc7d2fe445a32d1319e7641c719267a2c4669da2a71ac03b86021d943c",
"iat" : 1750751069,
"enc" : "user",
"data" : "ZXlKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWVd4bklqb2laR2x5SW4wLi5wbzNyZHd4SjVSMGQ5RUpXLldPaXBnT0tVNUlZU0VVeXYua3lhZmlUajhSWmJya2ZiRVNpb0hxUQ==",
"client_id" : "https://example.com/wallet/1",
"kid" : "Ar2IGiWEJnjb57P2V4hLQIaDZuzmt54bN227obY5NSIL",
"context" : "hsm",
"type" : "hsm_list_keys",
"pake_session_id" : "e124475e1f39b9823dc6538fffd69193c75e784c7a90d253bca5404ad60ee9ca"
}
```

Decrypted JWE payload

```json
{
"curve" : [ ]
}
```

List HSM keys - service response

```json
{
"ver" : "1.0",
"nonce" : "8e85a3cc7d2fe445a32d1319e7641c719267a2c4669da2a71ac03b86021d943c",
"iat" : 1750751069,
"enc" : "user",
"data" : "ZXlKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWVd4bklqb2laR2x5SW4wLi5fdFRLTVU2a2tVa0UtSnhqLlp4WWFCQ0JjZjIyRDg4WVRDdk9SeU14OHBFWGxVaUpWYWpNU1NIb21qU0NEcG1yOXREYmNzVHNnTktVSGRfb2tTM3dEa1pwcThwWHFxT2xNRUs5WVlHRmlCV2I4Q1QzZlRNY0pJMFBtUzBPejhhNy1IcnJEMVM1WXhmSVVJYVFhd0NqYUhxR0t6U0w4Mk9WTldqcUJOR2M3by1kUEdFSXFERDNlWTB4MTN5OU5UaXl4S1lldnN0eVJveS0zQmtUTUQ1U0xlQlFFSmduVWpoWEU4clNkTnpwZ0RTV29QZ202cndBaGdHWFBBdmZZc216OGRMMndjNWdCSmxJMTBaSDJhNkZDeTQzaXBCX0gwRzg0dVRhZUhDbzJMcnQ3alp3NDdGZGVhUHZRY3ZzdEg2MDRaeG5FbzcwZ1hNd2V3ME12eGJ4bW5teV9BS2Q5UTFlLUVqcURXRmJOMWFkTkdzVnp6OTdZZ0tpM05TTVdwWGtfeTZOVkdTV2VuWWZ4by1QQWlObExrdVRYSXllQml6d2ZyMFY2c21ucC1UOVVEbzJjWjE0MHJhTnJoY2dnSnlVNEp2c1lpWjFlZTVacG14Y3dka3hlTlNRMlhCWXNxQndnTU0yWFkwRFRucURZc1plVnlyb0tSRGRLSnh4TFBqVFFEWkxBQmtxNDJuSVR4R3BxWjlub09idE51TzRtd0pWcVR4Mm5YRGhjUmhGNlVhZVNFZmdMTUR4dndaWDM5bUlLMEw2ZHVCUlhfQk82Nks4RTV0cG5LUzN0ZUJuUWFVWEdrSlJPczdKMGVuTUlTNHFzNE1XazlLbmxjM19jTDdmY0M4Y2ZXMENwVExyX2haVlRhRWN2LUN3NENjRm94Sm9MUlE0N1A0b3RHRFgtbWhDb3BMbzQ4LWJiZExJME9UckJIanFzVE51eERFNDFJR3IwVlpjcmlac3M1NnVqQTFHRjYzc3VGa1JGbjIxeE1OVFZJeWUxU1kxOTI1RElrNC1ISzNJY0NYdzZGOV9NbWtYNW1VTmh6QWkzeUhkTWVlS04yQnN3XzdSdG9UVVRWT01zZ0tzS1h5d3ZxSzFhcEhvWTZJTXVXNlgxUW5Ob24ycTZRaGV2WWcybmRUUHBUSlNtTmhUdDctU1RrOFpOMHRXNFRrRjZNNk5wMl9wakNEbjVhQkdSNnk2dlk3V0lyeWRIMUFrRUtzaDVKQl80dzdkQy1CZW5EenBreFotdGdOR0RBZlFVVVhoX3BaRnZmN3M1aTVTTXdIc1NVVXhYaThSZTNSRUdETDBNeWM5WmtYLUprSjNZcVFDeEZ3Ylk2X2VtZDRnQnA1WXprNlZ5VE5VU1c5Vk9nMFhXVlA3ZmNmd1dSV25FSmtoR21ZOGZUVVMzbHgwTmc3bUhhdGJmeXdSVHY0R09mTU1fMzFTVHRaazRTanNfTWtYSkNYRlFaYnZSekM4cllkd3A0VkVVWmJudnpTQ3pva05oSGpHSktCZ1RKam5GbG9ZOVV3OG5LUFVRcFRCXzMtY2p5Y3BQMVNhMVl1RWlNU1hIVTdlOG1Rd1ZnZVVreGJCdEgteDRjekpQOVV1cmlyUXo5MHRPM1lqMEFNbFVhQlBpb2NvVDJid0Ewc2xvT0phbTkzRFBkUzJzZkNxSnZVZTZGa1RuWWlrdFFuY0oyRzhXa1NnTEN2QWJueThlNXpqNy1DS1gyLUdwbENTQmRYVVhkb0pDV0lyY0Z3UkZzc3k4dHEzNWZpb3UtaWxSb2JoeTdGRnlyTkotbjdpbUczdXJrc2xDQlg3ajFaRkdzTUM3aEhXZmJHbFg1bzdRSnF5ejlaeHBNR01zVEEudHhHLWMwU005UUw2SktvaEpsTDMzZw=="
}
```

Decrypted JWE payload

```json
{
"key_info" : [ {
"kid" : "0308345940bc96d1ea6456ff753596281ff8cec4dfb0a1a82a0a3508b0ac5e17d8072b6bfcc17aa5e6d97d863f2017aa09",
"curve_name" : "P-384",
"creation_time" : 1750751069,
"public_key" : "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECDRZQLyW0epkVv91NZYoH/jOxN+woagqCjUIsKxeF9gHK2v8wXql5tl9hj8gF6oJ3MZ45jdnRNGIG8O+LtWMraR0irerNaHb165jC9+reCXRkVZLr0q7nvgbq18zxuoR"
}, {
"kid" : "03fbe636059033a07ee3099caf84a87474d94afa2c7d431f3391ebd8cf21a24216",
"curve_name" : "P-256",
"creation_time" : 1750751069,
"public_key" : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE++Y2BZAzoH7jCZyvhKh0dNlK+ix9Qx8zkevYzyGiQhYdmIZjwS5S9fMegmKL685ctyQMNS8Jh1QayMYzwpL4AQ=="
}, {
"kid" : "0301e5a88aca8d54fb87a52cdd5d6f4e8a16f147a10c133b7c4adc4cf3c867f68410d5de1582bc8d74d7f91853758931bd2c8badcd2ff9ab7b49832a4a058451c0a8d2",
"curve_name" : "P-521",
"creation_time" : 1750751069,
"public_key" : "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB5aiKyo1U+4elLN1db06KFvFHoQwTO3xK3EzzyGf2hBDV3hWCvI101/kYU3WJMb0si63NL/mre0mDKkoFhFHAqNIBQkoUyt32fqcaSSyf00VQvJHOKF8s7V8SF4HAJpTmFF53uGjoul02v6wy3LPlmKGYpfH/FJcK9/B3oqxDvI5ciis="
} ]
}
```


## 3 ECDSA Sign

### 3.1 Type identifier

The ECDSA sign service type is identified by the following type identifier:

> hsm_ecdsa

### 3.2 Service type data

This service type requests an ECDSA signature on a key that is available in the remote HSM.

The service request data includes an encrypted JWE where the payload holds a JSON object with the following parameters:

- `kid` : (**string**) - The key identifier of the HSM key.
- `tbs_hash` : The hashed data to be signed

The service response data includes an encrypted JWE where the payload is the bytes of the generated signature value

### 3.3 Example

Service request - ECDSA sign
```json
{
"ver" : "1.0",
"nonce" : "8d704945b58f8ec29de9f7ff01ae8c13598bdb7e77118f206b0076628a2416f0",
"iat" : 1750751794,
"enc" : "user",
"data" : "ZXlKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWVd4bklqb2laR2x5SW4wLi5YLVpGeXpjS3ZSdWsyc3JDLjRrbVJFLTFNZEhqZ0VOaWNDSkZjd1UwY1gxOHdUbTV1aDBZRVA3d2p0WGJJejBsSDZRdkdCU0Vqd1NCNk1ZYVdRNXVGRzNrR2FGMkxob0MwMlY0aXZIbTBhc2lLZlBIaDN1Qy1kSXNnenhVdWJGQjV1Wk9rTGEwSy1rU0hNWU1Oc0lNdExyMUpHTzlNclpYeWhFT1BKZ1R5TS1FdEtEMlJPeHVnVjl0WC1kU1ZTVmM5akh3Lmt5Mk41bk9IcktkekE2aGExVGdkQkE=",
"client_id" : "https://example.com/wallet/1",
"kid" : "Ar2IGiWEJnjb57P2V4hLQIaDZuzmt54bN227obY5NSIL",
"context" : "hsm",
"type" : "hsm_ecdsa",
"pake_session_id" : "2fd8e97a48d5b26641cfb236bb174e9751507429a252a757313438991ef989f0"
}
```

Decrypted JWE payload

```json
{
"kid" : "02205fb03627f3d6f2100c5c2f156cd8c8da828c168ba7bac39188ac40d648a5dc",
"tbs_hash" : "YUHJYghlxa4CTkBEKvtPmiA+jCMUURknHs19sd7bNjs="
}
```

Service response - ECDSA sign
```json
{
"ver" : "1.0",
"nonce" : "8d704945b58f8ec29de9f7ff01ae8c13598bdb7e77118f206b0076628a2416f0",
"iat" : 1750751794,
"enc" : "user",
"data" : "ZXlKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWVd4bklqb2laR2x5SW4wLi5wUWNFVGh4b1ExbDdvUFdoLmxYSlBQcWNDNF9uYVpNb3ozYXdTeGpkbWxJeWpLczBuUFNTN0FMWkQ4R29DaGVDVWFiUFpLVkx2bFhxemFiS0dyM29Jd1hEYmlqeTBLQ0UwN0tiNEEwdTNmcHlPLXcubU9TV2VUTlVzZVFKLVdmQVBJSlJMQQ=="
}
```

Decrypted JWE payload

```text
30440220260a6228484119be74f7f8f46f964af0433b1f1218e667a92e82e45e48ef488d02207cfe73d85a7b81d7853aa680ba4a0ee17120f7fd87b7542b34f79863052abcbf
```

## 4 EC Diffie - Hellman

### 4.1 Type identifier

The Diffie-Hellman service type is identified by the following type identifier:

> hsm_ecdh

### 4.2 Service type data

This service type requests an Diffie-Hellman shared secret using a private key that is available in the remote HSM.

The service request data includes an encrypted JWE where the payload holds a JSON object with the following parameters:

- `kid` : (**string**) - The key identifier of the HSM key.
- `public_key` : The hashed data to be signed

The service response data includes an encrypted JWE where the payload is the bytes of the generated shared secret

### 4.3 Example

Service request - Diffie-Hellman
```json
{
  "ver" : "1.0",
  "nonce" : "97e5133a6b4f77f93a6d1d29295691d87c2279873d798051c606b3e32eb06028",
  "iat" : 1750752597,
  "enc" : "user",
  "data" : "ZXlKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWVd4bklqb2laR2x5SW4wLi5QVkdkVDVZUzJQR0ZrMmdDLnktRHJMTS1LRDd0R095Qjl4ZEVOUm9DaWVmVm1FcFdrblBZN0F1YzBkU0dmZ3NITmVGcmtCSzNhVDdEZ3VLLUItTWljZzRoZ2JXSU43UTNDeU92cGxkY0RqSm1ZWmE0cDBsbUQ3bExMSzhSX2ZXQ2xOTVZnU3V6TnpIb2FhVUZCb05YV1o2TkpFV2hrM1JXZmZKYm1RbmY4V3FSdHpEb0ZVQTFrS205NU9seTJ4TFo2dVZuX3JrbFk0YmxNTmNqOThSd2tRYjJWYUpFeDJpZDlrTHExencxeFl6Tk9NdWNoX3B4TWpDRm9BbE41WGc3VzYxLXFxbV9RTFgtMkk0MGhmTnBzdjFRaWhJbTF4TjBmallTVk1lZWQ5Qnl4T09pdS5RT2ZuYm1PZE5IT2Y4ZVdNYm4yXy1n",
  "client_id" : "https://example.com/wallet/1",
  "kid" : "Ar2IGiWEJnjb57P2V4hLQIaDZuzmt54bN227obY5NSIL",
  "context" : "hsm",
  "type" : "hsm_ecdh",
  "pake_session_id" : "5855db90562035cc3999c0dd1b5a5141b16f6180b8e573ce2699536dcbeb75f7"
}
```

Decrypted JWE payload

```json
{
  "kid" : "0294ddc3fd5554688bf619987b63bbb09b13e0d04b8a9da493309eef3f41767228",
  "public_key" : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETpEgaHsA2UTbSkn7hJb3KfvrlAMb+p715Gw/q5x01ZgQZWL7xURVYB9Fw+B7TK+GYMShDJYjLlKva5f+KkTx3w=="
}
```

Service response - Diffie-Hellman
```json
{
  "ver" : "1.0",
  "nonce" : "97e5133a6b4f77f93a6d1d29295691d87c2279873d798051c606b3e32eb06028",
  "iat" : 1750752597,
  "enc" : "user",
  "data" : "ZXlKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWVd4bklqb2laR2x5SW4wLi5qOEZqbTRwaVdXRmVuTnM0LnFzRFptMS0tZVluOGlnN0Zfd19EUlo1WVlEaXpZakVEdHhiV3BSTHVSaGMuMUx5ODgtaEpIT0JiXzg4NFE1RWZiQQ=="
}
```

Decrypted JWE payload

```text
ad91d860a109cce0e7d334813f434be8d44a21f8b3677cfe00c25fb572950687
```