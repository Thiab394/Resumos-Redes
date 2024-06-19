# Resumo P3
- Multimedia Networking
- Segurança
- Revisões Gerais do conteudo do semestre

## Multimedia Networking

### Aplicações Multimedia
- **Audio**<br>
    - Sinal analogico de audio amostrado em uma frequencia constante, cada amostra é quantizada em bits<br>
    - Receptor converte bits em sinal
- **Video**
    - Sequencia de imagens em uma frequencia constante
    - pixel = bits
    - codificação usa redundancia espacial(interna) e temporal(externa) no frame, e pode ser em frequencia constante ou variavel
    - espacial = mandar uma vez a cor e quantas vezes ela se repete
    - temporal = mudar apenas pixels que trocaram de lugar em relação ao frame anterior
- **Tipos de aplicação**
    - streaming
        - Pode dar play antes de baixar o video inteiro, ex: youtube, netflix
    - conversacional
        - ex: discord
    - streaming ao vivo
        - ex: twitch

### Streaming de video armazenado
- **Como funciona**
    - O video esta armazenado e é transmitido para o cliente, porem com o delay de rede, a parte que o cliente está vendo fica bem atrás da que ja foi transmitida, assim o cliente podendo ver o video antes dele ser todo transmitido.
    - O video chega primeira em um buffer, e do buffer vai para a tela do cliente, claro que tudo isso tem delay.
    - buffer esse que serve para ter um video suave e evitar alguns erros, e é preenchido em uma taxa variavel, podendo causar congelamento do video.

- **UDP**
    - Envio é feito a uma taxa compativel com o cliente
    - Menor delay de playout(menos jitter)
    - possivel problema com firewall
- **HTTP**
    - Enviado a taxa maxima compativel com banda do cliente, em conexão TCP
    - maior delay de playout(mais suave)
    - sem problemas com firewall
- **DASH**
    - Divide o video em blocos
    - cada bloco é transmitido em taxa diferente, pois constantemente verifica largura de banda do cliente e adapta a taxa de transmissao
    - prove URL para cada bloco
    - o Ciente "decide" quando mandar um bloco, em qual taxa(qualidade YT) e de onde
- **Rede de distribuição de Conteudo**
    - Mega servidor
    - Armazenar multiplas copias do video em sites bem espaçados geograficamente entre si, e enviar o mais proximo do cliente, usando authoritative DNS dos sites e do cliente.
        - tais sites podem ser escolhidos automaticamente como o mais proximo, ou com menos delay, ou o cliente decide a partir de uma lista
- **VOIP**
    - **Como funciona**
        - Ao falar, pacotes sao gerados, e enviados a cada 20 msec, com cabeçalho de camada de aplicação encapsulado em segmento TCP/UDP
        - podem existir perdas por causa da conexão e delay(pacote descartado pois chegou mto tarde)
    - **Delay de Reprodução Adptativo**
        - Estima o delay da rede, ajusta o delay de reprodução de acordo, procurando sempre evitar perdas.
        - no delay fixo ocorrem mais perdas
    - **Recuperar perda de Pacote**
        - Forward Error Conection
            - manda mais que o necessario, suficientes para se recuperar de um erro, sem retransmissão
            - pode recuperar até 1 pacote perdido
        - piggyback lower quality stream
            - envia informação redundante igual o FEC porem em qualidade baixa
        - Intercalar
            - divide os pacotes a cada 20msec para a cada 5msec assim caso um desses se perda, ainda existem boa parte do pacote original(15msec)
- **Protocolos para conversação em tempo real**
    - **RTP(Real time protocol)**
        - Coleta dados em blocos de 20msec(160bytes), adiciona cabeçalho RTP, encapsula tudo isso em um segmento UDP, nao garante nehuma qualidade de serviço como tempo de entrega(melhor esforço)
        - Cabeçalho RTP:
            - payload Type: tipo de codificação usado
            - numero de sequencia: +1 para cada pacote RTP enviado, detecta perda de pacote e restaura sequencia
            - Timestamp: permite sincronizar tempo entre diferentes pacotes de uma mesma transmissão
            - SSRC: identifica a fonte da transmissão(diferente para cada transmissão)
        - **RTCP**
            - Pacote de controle que auxilia o RTP e é enviado periodicamente para os participantes da sessão RTP
            - Pode sincronizar diferentes reproduções de midia em uma sessão RTP
            - Pacotes de relatorio do receptor, do emissor e descrição da fonte(ssrc)
            - usa 5% da largura de banda no trafego(95% na trasmissão de dados), dos quais 75% ficam pro receptor e o restante pro emissor
    - **SIP(Session iniciation protocol)**
        - Provê mecanismos de de configuração da chamada:
            - um cliente saber que o outro quer chama-lo
            - concordar com tipo de midia/codificação
            - finalizar chamada
        - determina o IP do cliente chamado
        - Gerenciamento da call
            - enviar midia, trocar codificação, convidar pessoas, etc
        - **Configurando Chamada com SIP**
            - Chamador manda convite para o IP de bob, contendo seu numero de porta, IP, e codificação(oes) que prefere
            - chamado responde com messagem OK, com seu numero de porta, IP, Codificação(oes) que prefere
            - agora as mensagens SIP podem ser enviadas em TCP ou UDP
            - Caso chamado nao tenha nenhuma das codificações preferidas pelo chamador, chamado envia mensagem listando os codificadores que ele possui e logo eles concordam em um
            - é possivel rejeitar uma chamada
        - **Tradução de nomes, localização do usuario**
            - se tiver apenas o nome ou email e precisar do IP, usa protocolo DHCP
            - Resultados variam de acordo com hora do dia, bloqueio de chamada e status de chamada do destinatario.
        - **SIP Registrar**
            - quando o cliente inicia o SIP, manda uma mensagem "SIP registrar" para o seu servidor
            - serve para registrar o cliente SIP na rede, para que outros possam localiza-lo e chama-lo
        - **SIP Proxy**
            - é ele que é responsavel por redirecionar as mensagens SIP para seu destino
            - dois clientes conversam pelos mesmos proxys
            - analogo a um servidor DNS com TCP configurado

- **Suporte de rede para multimedia**
    - implementa capacidade de enlace tal que congestionamento nao ocorra, trafego flui sem delay ou perda, alto custo de banda
    - **tirando o melhor do serviço de melhor esforço**
        - trafego nao é dividido, sendo todos os serviços juntos
        - trafego dividido em classes, a rede trata cada classe diferentemente
        - granularidade: serviço diferente entre multiplas classes, e nao entre conexoes individuais
    - **Principios para garantia de qualidade de serviço**
    - é necessario marcar o pacote para o roteador distinguir entre classes diferentes, e aplicar as politicas.
    - isolar uma classe da outra
    - enquanto prove isolamente, usar os recursos da melhor maneira possivel
    - se a rede nao cumprir os requisitos do fluxo de dados, ela deve bloquear a chamada(busy signal)
    - **Mecanismos de agendamento**
        - FIFO(first in first out)
            - politica de descarte: dropa o pacote que chegou, dropa baseado em prioridade ou randomicamente
        - Agendamento baseado em prioridade
            - multiplas classes com diferentes prioridades
        - Round Robin(RR)
            - passsa uma vez por cada classe(ciclico)
        - Enfileiramento com peso
            - Round Robin com peso/prioridade em cada classe
    - **Mecanismos de Policiamento**
        - tenta limitar o trafego para nao excede os parametros declarados, usando a taxa media, a taxa pico, e burst size
        - **Token Bucket**
            - pode segurar até B tokens
            - tokens sao gerados a menos que o balde esteja cheio
            - usado para controlar o input de tokens
    - Token Bucket e Enfileirament com peso, se combinam para garantir um limite superior no atraso(QoS)
    - **serviços diferenciados**
        - querem classes de serviço qualitativas
        - distinção de serviços igual as classes(prioridade)(platina,ouro,prata)
        - funções simples no nucleo da rede e complexas nos roteadores das pontas, ou hosts
    - **Diffserv**
        - roteadores das pontas:
            - gerencia o trafego por fluxo
            - marca pacotes como "In-profile" ou "out-profile"
            - marcação pode ser diferente para cada classe(class-based), ou diferente para fluxo que esteja em conformidade com as regras de politica e etc
        - roteadores do nucleo:
            - gerencia o trafego por classe
            - buffering e agendamento baseado na marcação feita nas pontas
            - in-profile tem preferencia
    - **PHB(Per-hop behavior)**
        - Encaminhamento acelerado
            - garante taxa minima de saida de pacotes para uma classe de trafego
            - pacotes recebem tratamento especial para garantir que sejam entregues o mais rapido possivel
        - Encaminhamento assegurado
            - divide o trafego em quatro classes, cada uma garantindo uma quantidade minima de largura de banda
            - cada uma possui três preferencias/politicas de descarte
            - garante um certo grau de qualidade para diferentes classes
# Segurança
- **Geral**
    - Confidencialidade
        - só o emissor e o recepetor pretendido devem entender o conteudo da mensagem
        - emissor criptografa a mensagem e o receptor descriptografa a mensagem
    - Autenticação
        - emissor e receptor querem confirmar suas identidades
    - Integridade da mensagem
        - emissor e receptor querem garantir que a mensagem nao foi alterada sem detecção
    - todos os serviços devem estar disponiveis pros usuarios
    - **Resumo de ataques**
        - eavesdrop: interceptar mensagens
        - inserir mensagens na conexão
        - personificação: fingir ser o endereço fonte no pacote(ou qualquer campo do pacote)
        - roubo: tomar a conexão tomando o lugar do emissor ou receptor
        - denial of service
- **Principios da Criptografia**
    - um texto é criptografado por meio de um algoritmo de criptografia utilizando uma chave K, tal texto criptografado chega no destino dele, e é descriptografado com um algoritmo de descriptografia utilizando uma chave K'
    - portanto a mensagem M deve ser igual á K'(K(M))
    - esquema basico de criptografia -> cifra de cesar(mais sofisticado = cifra de cesar * 4 ciclicamente)
    - **Chave simetrica**
        - dois clientes compartilham uma mesma chave, que é usada para criptografar e descriptografar a mensagem/dados
        - **DES**
            - é um tipo de block cipher/cipher block chaining(quer dizer a mesma coisa), que é uma criptografia em blocos de um tamanho especifico, nesse caso, 64bits
            - ele divide a mensagem em esquerda e direita, e permuta 16 vzs cada uma delas pegando 48 bits aleatorios da chave de 56 bits, junto com o lado direito da mensagem, e essa permutação vira o novo lado direito, e assim segue 16 vzs
            - nao é mto eficiente porém é válido, normalmente usam 3DES(Des 3 vezes)
        - **AES**
            - tem chaves de 128, 192 e 256 bits, e usa blocos de 128 bits
            - muito mais sofisticado que o DES
    - **Chave Publica**
        - basicamente cada pessoa possui uma chave publica e uma chave secreta/privada
        - ao tentar enviar uma mensagem para uma pessoa, voce ira criptografa-la com a chave publica dessa pessoa, ao chegar nela,ela ira descriptografa-la com a chave privada dela
        - dada uma chave publica K+ deve ser impossivel computar a chave privada K-
        - **RSA**
            - criptografar uma mensagem é igual criptografar um número(bits)
            - escolha P e Q que sejam primos grandes(1024 bits)
            - n = p*q, z = (p-1)*(q-1)
            - escolha um E menor que N que nao tenha fator comum com Z(relativamente primos)
            - escolha D tal que E*D mod Z = 1(D é o inverso multiplicativo de E mod Z e vice versa)
            - chave publica é (n,e) e privada é (n,d)
            - para criptografar é "c(cifra)= m^e mod n" e descriptografar é "m=c^d mod n"
            - **propriedade importante**: K-(K+(m)) = K+(K-(m))
            - dois clientes podem usar RSA para trocar a chave simetrica e dai começar a usa-la
- **Autenticação**
    - **ap4.0**
        - nonce: numero usado apenas uma vez
        - alice manda mensagem "i am alice", bob manda o nonce para alice, que é gerado pelo bob, alice retorna o nonce criptografado com a chave compartilhada deles, portanto bob pode usa-la para descriptografa-la e ver a mensagem original
        - é usado para autenticação WEP
    - **apto5.0**
        - mesma coisa do primeir só que usando a tecnica de chaves publicas
        - ou seja, alice criptografa com a chave privada dela, e bob usa a chave publica de alice para descriptografar e garantir que alice é realmente alice
        - é suscetivel ao man-in-the-middle
- **Integridade da mensagem**
    - **Assinaturas digitais**
        - emissor assina digitalmente o documento, dizendo que ele é o dono/criador, isso é verificavel e nao forjavel(idealmente).
        - ex: bob assina um documento com a chave privada dele(K-), alice verifica que bob assinou com sua chave publica(k+)(mesmo esquema de chave publica)
    - **Resumo da mensagem**
        - é caro criptografar uma mensagem grande com chave publica, portanto utiliza-se uma função Hash para diminui-la(tamanho fixo)
        - e tambe dificulta o atacante em saber qual é a mensagem
        - algoritmos de Hash: MD5(128 bits) e SHA-1(160 bits)
        - **Algoritmo para enviar msg:**
        - normalmente isso é utilizado junto da assinatura digital, de tal modo que uma mensagem grande passa pela hash, logo dps é criptografada pela chave privada logo vc tem K-(H(m))
        - o emissor manda essa mensagem criptografada e a mensagem original pura, ao chegar no destinatario, ele descriptografa com a chave publica do emissor e obtem H(m)
        - ele passa a mensagem pura recebida pela função hash e compara os dois H(m), se forem iguais ta tudo certo
    - **Certificado de chave publica**
        - CAs(autoridade de certificação) linkam chaves publicas para entidades particulares(clientes)
        - **Como Funciona**
            - pessoa manda informações de identificação(CPF)
            - CA cria um certificado de chave publica pra pessoa q requisitou
            - tal certificado é assinado pela chave privada do CA(criptografado)
            - para descriptografar basta usar a chave publica do CA
- **Email seguro**
    - **Enviando email seguro**
        - alice criptografa a mensagem(email) com uma chave simetrica gerada aleatoriamente, gerando Ks(m)
        - alice tambem criptografa a chave simetrica com a chave publica do bob(K+), gerando Kb+(Ks) e envia os dois pro bob pela internet
        - bob usa sua chave privada para descriptografar a chave simetrica e usar a chave simetrica para descriptografar a mensagem
    - **enviando autenticação**
        - igual o algoritmo para enviar mensagem acima
        - tem outra maneira onde a alice passa a mensagem pelo hash e pela sua chave privada, obtendo Ka-(H(m)) e envia isso junto com a mensagem pura para ser criptografada pela chave simetrica (Ks), obtendo Ks(m) e Ks(Ka-(H(m)))
        - e tambem criptografa a chave simetrica com a chave publica do bob, gerando Kb+(Ks)
        - o bob vai usar a chave privada dele para pegar a chave simetrica, usa-la para pegar o (Ka-(H(m))), usar a chave publica da alice para obter H(m)
        - depois usar a chave simetrica para obter m a partir de Ks(m) e passar pela hash pra virar outro H(m) e comparar os dois H(m)
- **Protegendo conexão TCP: SSL**
    - SSL(secure sockets layer), prove uma API para aplicações
    - **Toy SSL**
        - Handshake: alice e bob usam seus certificados e/ou chaves privadas para se autenticarem e trocarem o segredo compartilhado
        - alice após enviar o "hello" pro bob e receber seu certificado e nonce, envia o segredo mestre criptografado com a chave publica do bob, a partir disso o handshake esta feito e podem trocar dados
        - derivação de chave: os dois derivam chaves do segredo compartilhado.<br> utilizam quatro chaves, 2 pro cliente e 2 pro servidor, kda um possui uma chave de criptografia e uma chave MAC, e deriva essas chaves usando KDF(key derivation function), que pega o segre mestre(compartilhado) e mas dados aleatorios e cria as chaves
        - trasferencia de dados: é quebrado em varias partes(registros)
        - existe uma mensagem especial para fechar conecção
        - **Registro de Dados**
            - no toy quebra-se o fluxo de dados em uma série de registros, cada um com um MAC, com sua parte de dados e a parte de comprimento
            - para evitar atque de retransmissão dos registros ou de reordenação, coloca-se um numero de sequencia no MAC
            - para evitar ataque de fechamento de conexão TCP coloca-se o tipo de registro em um campo no registro, 0 para dados e 1 para fechamento
    - **SSL suite de cifras**
        - cliente e servidor concordam na suite de cifras a ser utilizada
        - as mais comuns são: <br>Simetricas: DES, 3DES, RC2, RC4  <br>Publicas: RSA
    - **Handshake do SSL real**
        - cliente manda lista de algoritmos suportados e o seu nonce
        - servidor escolhe os algoritmos da lista e manda de volta a escolha com certificado com o nonce do servidor
        - cliente verifica certificado, extrai chave publica do servidor, e gera o pre-master-secret, criptografa ele com a chave publica extraida e manda pro servidor
        - cliente e servidor geram as chaves de criptografia e mac suas(referenciadas la em cima) do pre-master-secret e nonces
        - client e servidor se mandam um MAC de todas as mensagens do handhshake ate o momento(Criptografadas)(util pra evitar adulteração)
    - nonce do cliente, do servirdor e a pre-master-secret, sao colocados em um gerador de numero pseudo aleatorio que produz o master secret
- **IPsec**
    - IPsec é utilizado majoritariamente com VPN
    - provê: integridade de dados, autenticação da origem, prevençao de ataque de retransmissão e confidencialidade
    - possui dois protocolos: AH(Authentication Header) e ESP(Encapsulation Security Protocol)
        - AH: Provê autenticação e integridade de dados, mas nao confidencialidade
        - ESP: provê confidencialidade também, logo é mais usado
    - possui dois modos
        - modo de transporte: datagrama IPsec emitido e recebido pelos end-systems
        - modo de tunelamento: hosts e roteadores de borda ligados para receber datagrama IPsec
    - basicamente só o modo de tunelamento com ESP importa
    - **SA**
        - antes de mandar dados estabelece uma "assosiação segura(SA)" do emissor pro receptor, só tem uma direção(simplex), como se fosse um tunel seguro onde pode se passar as informações
        - nesse tunel é definido o protocolo de segurança(AH ou ESP), os algoritmos criptograficos, chaves criptograficas, parametros de segurança usados, e a identificação do SA(SPI+AH/ESP+IP de destino)
    - **SAD(Security association database)**
        - os endpoints guardam o estado do SA no SAD, para localiza-lo durate os processos
        - quando for mandar um datagrama IPsec, o emissor acessa o SAD para determinar como processar o datagrama
        - quando chega no receptor, ele examina o SPI do datagrama, indexa o SAD com o SPI e processa o datagrama de acordo
    - **Datagrama IPsec**
        - o datagrama original possui apenas 2 campos, o cabeçalho de IP e o payload do datagrama(dados)
        - no datagrama IPsec adicionamos novos campos
        - **ESP trailer**
            - serve para preencher com dados aleatorios os espaços necessarios para utilizar os algoritmos de cifração por bloco(CBC)
        - **ESP Header**
            - SPI: é ele que carrega os parametros definidos pelo SA(explicados acima), por isso o receptor precisa lê-lo para saber o que fazer com o datagrama
            - Sequence number: evitar ataques de retransmissão
        - **ESP auth**
            - possui o MAC(Message Authentication Code), usado para garatinr integridade e autenticidade da mensagem, gerado nesse caso pela chave secreta compartilhada
    - **SPD(Security Policy Database)**
        - informações no SPD indicam o que fzr com o datagrama, e informações no SAD indicam como fazer
    - **IKE(internet Key Exchange)**
        - Estabelece um SA IPsec automaticamente, antes era manualmente
        - **Fase 1(lento e pesado)**
            - começa com autenticação, usando PSK(Pre shared key) ou PKI(chaves publicas ou privadas e certificados), qualquer um dos dois escolhidos, os dois lados começam com o "segredo"
            - Usar criptografia assimetrica(publica) para concordar e criar uma chave simetrica(pois criptografia simetrica é mais rapido)
            - IKE SA criado(tunel da fase 1)
        - **Fase 2(rápido)**
            - usa as chaves simetricas concordadas na fase 1 para concordar no metodo de criptografia e chaves criptograficas e o resto que o SA provê, para assim poder transferir dados
            - a partir disso ele cria um SA IPSEC(tunel da fase 2), com todas as concordancias e politicas presentes, rodando em cima do tunel da fase 1
            
- **Protegendo LANs wireless**
    - provê confidencialidade, autorização de host e integridade
    - Capa pacote é criptografado separadamente, podendo descriptografar mesmo tendo perido o pacote anterior
    - a cifra pode ser obtida a partir da keystream(gerador de keystream) xor mensagem(C = ks XOR M), e a mensagem também segue o mesmo principio, para que isso aconteça, ambas precisam ir caractere por caractere e sequencialmente, garantindo que a cifra seja unica
    - **Criptografia WEP** 
        - emissor calcula o ICV(integrity check value)
        - cada lado possui uma chave simetrica de 104 bits, o emissor cria um IV(initialization vector) de 24 bits e coloca junto da chave -> chave de 128 bits
        - emissor tambem anexa o KeyID
        - a chave passa por um keystream generator para gerar um keystream
        - os dados do quadro + ICV sao criptografas, e anexados ao IV e Key ID, assim criando o payload que é inserido no quadro 802.11
    - **Descriptografia WEP**
        - extrai o IV, usa o IV junto com a chave simetrica num gerator de numero aleatorio, pra pegar o keystream
        - com o keystrem consegue descriptografar os dados e o ICV
        - usa o ICV pra verificar integridade dos dados
    - **Quebrando criptografia WEP 802.11**
        - ja que o IV é um numero de 24 bits, ele eventualmente vai ser reutilizado
        - um atacante pode fazer com que a pessoa criptografe os caracteres da mensagem d1,d2.... assim o atacante vai saber os D(i)s e os C(i)s(cifra), entao ele pode computar as chaves K(i), sabendo assim a sequencia de chaves para cada caractere, logo quando o IV for reutilizado o atacante pode descriptografar a mensagem por completo
    - **802.11i modo de operação**
        - 1: desobre as capacidades de segurança entre o STA(cliente) e AP(Modem)
        - 2: cliente e o servidor de autenticação(AS), se autenticam, e juntos geram a Master Key(MK)
        - 3:cliente e o servidor derivam um par de master keys (PMK)
        - 4: cliente e o modem usam esse PMK pra derivar uma chave temporal(TK) usada para criptografar e descpritografar mensagens
    
- **Firewall e IDS**
    - é basicamente uma parede que permite entrada de alguns pacotes e bloqueia de outros de acordo com algumas regras pré determinadas
    - as regras englobam coisas como endereço fonte, endereço de destino, protocolo, porta fonte, porta de destino, e bit de flag
    - **stateless firewall:**
        - firewall que aceita pacotes que "nao fazem sentido" por um exemplo um pacote com bit ACK setado mesmo sem ter conexão TCP estabelecida
    - **Stateful Firewall:**
        - rastreia os status de cada conexão TCP, assim aceitando apenas pacotes que façam sentido(checa conexão antes de admitir)
    - **Gateway de aplicação**  
        - nao filtra só dados(pacotes), mas tambem o tipo de conexão, fazendo com que cada tipo de conexão tenha um gateway padrão para troca de dados naquela conexão, um para TCP, outro para UDP e outro pra IP
    - **IDS(intrusion detection Systems)**
        - inspeciona os conteudos dos pacotes profundamente, procurando por padrões de caracteres de string que remetem a virus conhecidos
        - também examina correlação entre multiplos pacotes, com o mesmo objetivo acima
        - existem varios IDSs em locais diferentes fazendo checagens diferentes, em conjunto com o firewall



# Revisões Gerais

## Caminho de um pacote atraves das camadas
- Camada de Aplicação (Host A):

O processo de aplicação no Host A gera dados a serem transmitidos.
Os dados são passados para a camada de transporte.

- Camada de Transporte (Host A):

A camada de transporte segmenta os dados em pacotes e adiciona cabeçalhos TCP ou UDP.
Os pacotes são passados para um datagrama na camada de rede.
- Camada de Rede (Host A):

A camada de rede adiciona cabeçalhos IP aos pacotes, incluindo o endereço IP de destino (Host B).
Os pacotes são passados para a camada de enlace.
- Camada de Enlace (Host A):

A camada de enlace adiciona cabeçalhos de enlace (como cabeçalhos Ethernet) aos pacotes, incluindo o endereço MAC de destino do próximo salto na rota.
Os pacotes são transmitidos fisicamente para o próximo dispositivo na rede.
- Camada Física (Host A):

Os pacotes são transmitidos através do meio físico da rede, como cabos ou sinais sem fio, para o próximo dispositivo na rota.
- Camada Física (Roteadores Intermediários):

Os pacotes passam por uma série de roteadores intermediários, onde cada roteador realiza as mesmas operações de camadas de rede e enlace.
- Camada de Enlace (Roteador Final antes do Host B):

O último roteador antes do Host B recebe os pacotes e os encaminha para a interface correta na rede local do Host B, adicionando cabeçalhos de enlace conforme necessário.
- Camada de Rede (Roteador Final antes do Host B):

O último roteador consulta sua tabela de roteamento e encaminha os pacotes para a interface conectada à rede local do Host B.
- Camada de Enlace (Host B):

A camada de enlace do Host B recebe os pacotes e os encaminha para a camada de rede se o endereço MAC de destino corresponder ao seu próprio endereço MAC.
Os pacotes são passados para a camada de rede.
- Camada de Rede (Host B):

A camada de rede do Host B recebe os pacotes, verifica o endereço IP de destino e encaminha os dados para a camada de transporte.
- Camada de Transporte (Host B):

A camada de transporte reúne os segmentos de dados recebidos e os passa para a camada de aplicação no Host B para processamento final.


