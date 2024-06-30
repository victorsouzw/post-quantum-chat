### Sobre a aplicação
- A aplicação simula um chat com cifra post-quantum ponta a ponta.
- A comunicação eh realizada via socket cliente servidor, é projetada para atender apenas dois usuários, 
- Visa pura e unicamente a demonstração da aplicação de KEMs, ilustrando uma criptografia ponta a ponta resistente a ataques quânticos. 

### Sobre a criptografia
- Cliente gera par de chaves e envia chave publica para o servidor.
- Servidor gera segredo encapsulado com o KEM CRYSTALS - Kyber (finalista PQC NIST).
- Armazena o segredo e envia o encapsulamento deste para o client.
- Client usa chave privada para extrair o segredo do encapsulamento.

- Segredo estabelecido, comunicaçÃo pode ser iniciada.
- Mensagem eh cifrada antes de enviar, e decifrada pela outra ponta utilizando AES com o segredo compartilhado, o qual não se baseia nos problemas de logaritimo discreto ou de fatoração de primos, sendo assim não será quebrado pelos ataques quânticas, possivelmente sendo necessário apenas aumentar o tamanho das chaves.

### Ao executar
- Crie um fat jar, com todas dependências contidas, com o comando: ```mvn clean compile assembly:single```
- Digite 1 no id de uma das execuções para ser o servidor e qualquer outro id na execucação do cliente.

### Disclaimer
- Aplicação não foi projetada para ser utilizada em produção, apenas para fins de estudo, conta com claramente com furos de arquitetura e design, visto que não era o enfoque do trabalho. Entretanto pode servir a comunidade com snippets de código para implementação de KEMs.