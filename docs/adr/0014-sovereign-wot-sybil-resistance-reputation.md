# ADR-0014: Sovereign Web-of-Trust Sybil Resistance & Reputation (ark-wot / ACP-04)

## Status
Accepted

## Context
Em redes ponto-a-ponto descentralizadas e sem permissões centrais (permissionless), ataques Sybil constituem a principal ameaça existencial: uma entidade maliciosa pode gerar milhões de identidades criptográficas virtuais a custo negligenciável, dominando tabelas de roteamento, rotas de tunelamento (`ark-vpn`), consensos de nomes (`ark-dns`), persistência de blobs (`ark-blob`) ou filas de computação (`ark-paas`).

Sistemas clássicos recorrem a autoridades centrais de certificação (X.509/PKI), consenso global de Proof-of-Work intensivo em energia, ou Proof-of-Stake oligopolista. No ecossistema ARK soberano, cada nó opera sem uma autoridade central arbitrária, exigindo um modelo de Web-of-Trust (WoT) estritamente resistente a ataques Sybil e a coligações de nós falsos (*collusion rings*).

## Decision

1. **Grafo de Confiança Local Subjetivo (Personalized PageRank / Subjective Trust)**:
   - Rejeição de matrizes ou scores de reputação globais uniformes: a confiança é intrinsecamente subjetiva do ponto de vista de cada nó (`local_root = node_ark_id`).
   - A avaliação de confiança é computada localmente com base nas atestações directas do operador do nó e na propagação transitiva com fator de amortecimento $\alpha = 0.85$ e horizonte estrito de saltos (máximo 4 a 6 hops).
   - Anéis de identidades Sybil desconectados ou com poucas pontes para a vizinhança confiável do nó local veem a sua influência limitada pelo gargalo das arestas de corte (*cut edges*).

2. **Atestações de Confiança Criptográficas PQC (FIPS 206 FN-DSA-512)**:
   - Declarações de confiança estruturadas como `TrustAttestation` assinadas com FN-DSA-512:
     - `issuer_id`: `ArkId` do nó emissor.
     - `subject_id`: `ArkId` do nó sujeito avaliado.
     - `score_weight`: Peso de confiança normalizado $[0.0, 1.0]$.
     - `capability_scopes`: Bitmask/vetor de escopos permitidos (ex: `RELAY`, `STORAGE`, `COMPUTE`, `DISCOVERY`).
     - `issued_at_pmt` & `expires_at_pmt`: Janela de validade vinculada ao Peer-Median-Time (`ark-time`).
     - `nonce`: Prevenção de duplicados.
   - Envelopadas canonicamente sob `KIND_WOT_ATTESTATION = 0x000A` (Retention Class 3 - Replaceable Parameterized indexado por `(issuer_id, subject_id)`).

3. **Decaimento Temporal de Confiança (Exponential Half-life)**:
   - Atestações atenuam a sua influência ao longo do tempo através de decaimento exponencial:
     $$w(t) = w_0 \cdot 2^{-\frac{\Delta t_{\text{PMT}}}{\tau_{1/2}}}$$
     com meia-vida padrão $\tau_{1/2} = 30\text{ dias}$.
   - Força os nós emissores a renovarem periodicamente as suas atestações ativas para manter a pontuação de confiança transitiva.

4. **Revogação Criptográfica Instantânea e Prioritária**:
   - Mensagens de revogação explícita `TrustRevocation` (`KIND_WOT_REVOCATION = 0x000B`, Retention Class 1/5) cancelam imediatamente atestações anteriores do mesmo emissor.
   - Revogações têm propagação prioritária e truncam instantaneamente caminhos transitivos no cálculo de grafos locais.

5. **Classificação Multicamada de Confiança (*Trust Tiers*)**:
   - Mapeamento determinístico da pontuação contínua de reputação $S \in [0.0, 1.0]$ e distância $d$:
     - **`CorePeer`** ($S \ge 0.85, d \le 1$): Nós próprios, familiares ou homelab primários. Acesso total, prioridade máxima em fila e sem restrições de tráfego.
     - **`Trusted`** ($0.50 \le S < 0.85, d \le 2$): Pares comunitários próximos. Acesso preferencial para armazenamento e relays.
     - **`Probationary`** ($0.15 \le S < 0.50, d \le 4$): Pares distantes mas conectados transitivamente. Sujeitos a rate-limiting moderado e exigência de pequenos comprovativos de PoW.
     - **`Untrusted`** ($S < 0.15$ ou desconectado): Acesso estritamente racionado, tráfego VPN negado por omissão, tarefas PaaS recusadas.

6. **Fachada Unificada `WotEngine`**:
   - Exposição de uma API determinística em `crates/ark-wot`:
     - `evaluate_trust(target: &ArkId) -> TrustEvaluation`
     - `record_attestation(attestation: TrustAttestation) -> Result<()>`
     - `revoke_attestation(revocation: TrustRevocation) -> Result<()>`
     - `sync_subgraph(&self, since_pmt: u64) -> Vec<TrustAttestation>`

7. **Computação Incremental Event-Driven e Caching em Memória**:
   - As avaliações de confiança são cacheadas em memória (`DashMap<ArkId, TrustEvaluation>`) garantindo latência $\mathcal{O}(1)$ no caminho crítico de inspeção de pacotes e RPCs.
   - O recálculo incremental ocorre assincronamente acionado por eventos de mutação (receção de novas atestações, revogações prioritárias ou avanço de ticks de decaimento PMT).

8. **Persistência Híbrida (Fjall LSM Keyspace + Sincronização CRDT MST)**:
   - Persistência durável local realizada em keyspaces dedicados do `ark-storage` (`wot_attestations` e `wot_revocations`).
   - Difusão e reconciliação entre pares operada de forma transparente via `ark-crdt` (MST) e envelopes de fofoca (*gossip*) com verificação de assinatura pós-quântica.

9. **Normalização Estocástica de Grau de Saída (Anti-Dilution Sybil Constraint)**:
   - Para prevenir a multiplicação artificial de influência por emissores maliciosos, a matriz de transição aplica normalização estocástica dos pesos de saída de cada nó ($\sum_{j} w_{i \to j} \le 1.0$), garantindo conservação de probabilidade no passeio aleatório de Personalized PageRank.

## Consequences

### Positive
- Proteção robusta contra ataques Sybil sem necessidade de autoridades centralizadas ou blockchains externas de alto consumo.
- Decaimento temporal automático previne que identidades abandonadas ou chaves antigas mantenham privilégios indefinidos.
- Integração uniforme com QoS de VPN, armazenamento de blobs e autorizações de computação sandboxed.

### Negative / Trade-offs
- O cálculo de Personalized PageRank exige processamento local e caching de matrizes esparsas de adjacência.
- Novos nós soberanos sem conexões sociais diretas iniciam em modo `Untrusted`/`Probationary`, necessitando de pelo menos uma atestação inicial ou introdução por um nó conhecido.
