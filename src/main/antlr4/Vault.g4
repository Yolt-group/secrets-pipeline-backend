grammar Vault;

@header {
package antlr4;
}

start
  : annotation+
  ;

annotation
 : template
 | secret
 ;

secret
  : 'vault.hashicorp.com/agent-inject-secret-' name ':' secretReference
  ;

template
  :  'vault.hashicorp.com/agent-inject-template-' templateName ':' '|'
    templateBody
  ;

templateName
  : IDENTIFIER
  ;

templateBody
  : secretsPipeline
  | other
  ;

name
  : IDENTIFIER
  ;

other
  : '{{' secretPath commonName? '}}'
    '{{-' templatePart '-}}'
    '{{ end }}'
  ;

secretsPipeline
  : '{{-' secretPath cipherText context '-}}'
    secretType
    '{{' templatePart '}}'
    publicPart?
    '{{- end -}}'
  ;

context
  : '"' BASE64_STRING '"'
  ;

templatePart
  : IDENTIFIER
  ;

publicPart
  : '----------' base64PublicPart
  ;

base64PublicPart
  : BASE64_STRING
  | IDENTIFIER
  ;

secretType
  : 'type:' secretTypeIndicator
  ;

secretTypeIndicator
  : 'KEY_128'
  | 'KEY_160'
  | 'KEY_192'
  | 'KEY_224'
  | 'KEY_256'
  | 'KEY_512'
  | 'RSA_2048'
  | 'RSA_4096'
  | 'GPG'
  | 'GPG_PAIR'
  | 'PASSWORD_ALFA_NUMERIC'
  | 'PASSWORD_ALFA_NUMERIC_SPECIAL_CHARS'
  | 'CERT_ANY_IMPORT'
  | 'CSR'
  | 'JWKS'
  ;

secretPath
  : 'with secret "transit/git/decrypt/' path '"'
  ;

path
  : (IDENTIFIER ('/')*)+
  ;

cipherText
  : '"ciphertext=' vaultCipherText '"'
  ;

vaultCipherText
  : 'vault:v1:' (IDENTIFIER | BASE64_STRING)
  ;

commonName
  : '"' BASE64_STRING '"'
  ;

secretReference
  : '"' IDENTIFIER '"'
  | '""'
  ;

commandBody:
  IDENTIFIER
  ;

IDENTIFIER
 : ('a'..'z' | 'A'..'Z' | '_' | '-' | '.' | '0'..'9')+
 ;

BASE64_STRING
 : ( '/' | 'a'..'z' | 'A'..'Z' | '+' | '=' | '0'..'9')+
 ;

WS  : (' '|'\t' | '\n')+ -> skip;

ErrorChar : . ;