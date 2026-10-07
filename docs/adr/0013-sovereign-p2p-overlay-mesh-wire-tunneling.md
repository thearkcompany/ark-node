# ADR-0013: Sovereign P2P Overlay Mesh & Post-Quantum Wire Tunneling (ark-vpn / ACP-07)

## Status
Accepted

## Context
A soberania de nós na rede ARK exige que nós em diferentes redes físicas (residências, redes móveis, centros de dados, homelabs) consigam comunicar-se diretamente como se estivessem na mesma rede local, sem depender de VPNs corporativas centralizadas, nós de saída de terceiros ou autoridades de certificação tradicionais.

Anteriormente foram definidos os blocos de persistência (`ark-storage`, ADR-0008), consistência distribuída (`ark-crdt`, ADR-0009), resolução soberana de nomes (`ark-dns`, ADR-0010), armazenamento distribuído de blobs (`ark-blob`, ADR-0011) e computação sandboxed (`ark-paas`, ADR-0012). No entanto, o roteamento ponto a ponto seguro na camada de rede IP (Camada 3) carecia de especificação unificada para tunelamento, IPAM determinístico, traversals de NAT/CGNAT e controlo de acesso Zero-Trust.

## Decision

1. **Abstração de Interface TUN Virtual (`VirtualTunAdapter`)**:
   - Implementar uma abstração modular de interface TUN de Camada 3 (`VirtualTunAdapter`).
   - Em sistemas operacionais com privilégios de rede, provisionar a interface de sistema `ark0`.
   - Para ambientes de CI, containers unprivileged e sandboxes (como `ark-paas`), fornecer um backend `MockTunAdapter` / in-memory loopback sem privilégios `CAP_NET_ADMIN`.
   - MTU da interface TUN configurado estritamente em **1.200 bytes** (com TCP MSS clamping) para garantir que pacotes IP encapsulados em cabeçalhos de segurança ARK nunca excedam o **Safe MTU de 1.280 bytes** da rede pública.

2. **Sovereign IPAM Determinístico (Dual-Stack)**:
   - Todo o nó participante deriva deterministicamente o seu endereço IPv6 Unique Local Address (`fd00::/8`) a partir do seu identificador canónico `ArkID` (`SHA3-256(PublicKey)`).
   - Mapeamento determinístico complementar de endereço IPv4 CGNAT (`100.64.0.0/10`) no espaço de nós do mesmo cluster para compatibilidade com ferramentas legadas que não suportem IPv6.
   - Eliminação completa de servidores centrais de DHCP; alocação determinística imutável e verificável em $\mathcal{O}(1)$.

3. **Post-Quantum Mesh Tunneling (PQMT)**:
   - Os pacotes de dados tunelados utilizam o stack criptográfico pós-quântico nativo do ARK (FIPS 203 ML-KEM-768 para estabelecimento de chaves de sessão + FIPS 206 FN-DSA-512 para autenticação de nós).
   - O tráfego de dados é encapsulado em envelopes `ArkEnvelope` com os novos identificadores canónicos:
     - `KIND_VPN_DATA = 0x0008` (Carga útil de pacotes IP encapsulados).
     - `KIND_VPN_HANDSHAKE = 0x0009` (Negociação de canal de sessão e rotação de chaves).
   - Todos os envelopes VPN são classificados como **Retention Class 0 (Ephemeral/RAM-only)**, sendo despachados diretamente em memória e nunca gravados no motor de persistência Fjall LSM.

4. **Traversal de NAT e Sovereign Relay Fallback (DERP-style)**:
   - Os pares tentam primeiramente a conexão direta via UDP hole-punching / ICE.
   - Caso estejam sob NAT simétrico ou firewalls restritivos, o tráfego E2EE (cifrado ponta a ponta) é retransmitido através de nós guardiões de homelab autorizados sem que esses nós intermediários tenham visibilidade sobre o tráfego limpo.

5. **Endpoint Roaming Transparente**:
   - Atualização dinâmica da tabela de sessões (`(peer_ark_id) -> (physical_socket_addr)`) ao receber envelopes válidos assinados e verificados pelo `SenderKeyID` com contadores de sequência não replicados, assegurando continuidade de sessão em transições de rede (ex: Wi-Fi para dados móveis).

6. **Micro-segmentação Zero-Trust (Mesh ACLs)**:
   - Motor de regras locais `VpnSecurityPolicy` aplicando micro-segmentação baseada em `(source_ark_id, destination_port, protocol, action)`.
   - Por omissão, tráfego inter-dispositivos do mesmo proprietário (cluster homelab) é aceite automaticamente, enquanto nós convidados ou externos estão sob política padrão de recusa (*Default Deny*), exigindo autorização explícita de portas/serviços.

## Consequences

### Positive
- Conectividade transparente entre todos os dispositivos do ecossistema ARK em qualquer lugar do mundo.
- Resistência quântica nativa para todo o tráfego de rede IP.
- Zero configuração de IPAM sem colisões graças à derivação direta do `ArkID`.
- Desempenho em velocidade de linha sem overhead de I/O em disco devido à Retention Class 0.

### Negative / Trade-offs
- O MTU de 1.200 bytes reduz ligeiramente a eficiência de payload TCP em relação a redes locais Gigabit puras de 1.500 bytes, mas garante interoperabilidade global sem fragmentação IP.
- Criação da interface TUN no host requer privilégios de administrador/root durante o setup inicial da interface no sistema operativo.
