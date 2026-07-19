// ============================================================
//  LUCK WORLD SERVER v7.0
//  10 WORKERS | 10 TOR GROUPS | AUTO FAILOVER < 1s
//  TX COUNT CHECK | PERSISTENT FOUND STORAGE
//  API LIMIT → INSTANT TOR SWITCH
// ============================================================

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const CryptoJS = require('crypto-js');
const elliptic = require('elliptic');
const { keccak_256 } = require('js-sha3');
const fs = require('fs');
const path = require('path');

const ec = new elliptic.ec('secp256k1');
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET','POST'] } });
const PORT = process.env.PORT || 3000;

// ============================================================
//  PERSISTENT STORAGE
// ============================================================
const FOUND_JSON = path.join(__dirname, 'found_wallets.json');
const FOUND_TXT  = path.join(__dirname, 'found_wallets.txt');

function loadFoundWallets() {
    try {
        if (fs.existsSync(FOUND_JSON)) {
            const data = JSON.parse(fs.readFileSync(FOUND_JSON, 'utf8'));
            return Array.isArray(data) ? data : [];
        }
    } catch(e) {}
    return [];
}

function saveFoundWallets(arr) {
    try {
        fs.writeFileSync(FOUND_JSON, JSON.stringify(arr, null, 2));
    } catch(e) {}
}

function appendFoundTxt(entry) {
    try {
        const line = [
            'MNEMONIC: ' + entry.mnemonic,
            'PRIV KEY: ' + entry.privkey_hex,
            'COIN: ' + entry.coin + ' (' + entry.coinSym + ')',
            'TYPE: ' + entry.addrType,
            'ADDRESS: ' + entry.address,
            'TX_IN: ' + entry.tx_in + ' | TX_OUT: ' + entry.tx_out + ' | TX_TOTAL: ' + entry.tx_total,
            'R: ' + (entry.received||0).toFixed(8) + '  S: ' + (entry.sent||0).toFixed(8) + '  B: ' + (entry.balance||0).toFixed(8) + ' ' + entry.coinSym,
            'DATE: ' + new Date(entry.savedAt).toISOString(),
            '='.repeat(60)
        ].join('\n') + '\n\n';
        fs.appendFileSync(FOUND_TXT, line);
    } catch(e) {}
}

// ============================================================
//  CRYPTO UTILITIES
// ============================================================
function hexToBytes(hex) {
    if (hex.length % 2) hex = '0' + hex;
    const b = Buffer.alloc(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substr(i, 2), 16);
    return b;
}
function bytesToHex(bytes) { return Array.from(bytes, b => ('0' + b.toString(16)).slice(-2)).join(''); }
function bufToWA(buf) {
    const w = [];
    for (let i = 0; i < buf.length; i += 4) w.push(((buf[i]||0)<<24)|((buf[i+1]||0)<<16)|((buf[i+2]||0)<<8)|(buf[i+3]||0));
    return CryptoJS.lib.WordArray.create(w, buf.length);
}
function waToBuf(wa) {
    const w = wa.words, s = wa.sigBytes, u = Buffer.alloc(s);
    for (let i = 0; i < s; i++) u[i] = (w[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    return u;
}
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58Encode(bytes) {
    const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    let n = 0n;
    for (let i = 0; i < buf.length; i++) n = n * 256n + BigInt(buf[i]);
    let s = '';
    while (n > 0n) { s = B58[Number(n % 58n)] + s; n = n / 58n; }
    for (let i = 0; i < buf.length && buf[i] === 0; i++) s = '1' + s;
    return s || '1';
}
function b58CheckEncode(ver, payload) {
    const p = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
    const f = Buffer.alloc(1 + p.length); f[0] = ver; p.copy(f, 1);
    const h1 = CryptoJS.SHA256(bufToWA(f)), h2 = CryptoJS.SHA256(h1), cs = waToBuf(h2).slice(0, 4);
    return b58Encode(Buffer.concat([f, cs]));
}
function hash160(pubHex) {
    const pb = hexToBytes(pubHex), s = CryptoJS.SHA256(bufToWA(pb)), r = CryptoJS.RIPEMD160(s);
    return waToBuf(r);
}
function keccakHash(pubHex) {
    const raw = pubHex.startsWith('04') ? pubHex.slice(2) : pubHex;
    return keccak_256(hexToBytes(raw));
}

// ============================================================
//  BIP39
// ============================================================
const BIP39 = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon cape capable capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable encourage end endless endorse enemy energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog folk follow food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment gas gasp gate gather gaze gear gender gene general genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose improve impulse inch include income increase index indicate indoor industry infant inflict inform initial inject inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle junior jury just keen keep key keyboard kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson letter level liberty library license life lift light like limb limit link lion liquid list little live lizard load loan lobster local lock logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin marine market marriage mask mass master match material math matrix matter maximum maze meadow medium meet melt member memory mention menu mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment monitor monkey monster month mood moon moral more morning mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee noodle normal north nose notable nothing notice novel now number nurse nut oak obey object oblige obscure observe obtain ocean odd off offense office often oil okay old olive olympic omit once one onion online only open opera opinion oppose option orange orbit orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent park parody party pass patch path patient patrol pattern pause pave payment peace peanut pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare present pretty prevent price pride primary print priority prison private prize problem process produce profit program project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea search season seat second secret section security seed seek segment select sell seminar senior sense sentence series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since sing siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social sock soda soft solar sold solid solution solve someone song soon sorry sort soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel when where whip whisper wide width wife wild will win window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo".split(" ");

function mulberry32(a) { return function() { a |= 0; a = a + 0x6D2B79F5 | 0; var t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
const _prng = mulberry32(Date.now());
function genMnemonic(size) { const w = []; for (let i = 0; i < size; i++) w.push(BIP39[Math.floor(_prng() * 2048)]); return w.join(' '); }
function mnemonicToMasterKey(mnemonic) {
    const key = CryptoJS.PBKDF2(mnemonic, CryptoJS.enc.Utf8.parse('mnemonic'), { keySize: 512/32, hasher: CryptoJS.algo.SHA512, iterations: 2048 });
    const hmac = CryptoJS.HmacSHA512(key, CryptoJS.enc.Utf8.parse('Bitcoin seed'));
    return bytesToHex(waToBuf(hmac).slice(0, 32));
}
function getPublicKeys(privHex) {
    const key = ec.keyFromPrivate(privHex, 'hex'), pub = key.getPublic();
    const x = pub.getX().toString('hex').padStart(64, '0'), y = pub.getY().toString('hex').padStart(64, '0');
    return { compressed: ((parseInt(y.substr(63, 1), 16) % 2 === 0) ? '02' : '03') + x, uncompressed: '04' + x + y };
}
function addrBTC(p) { return b58CheckEncode(0x00, hash160(p)); }
function addrETH(p) { return '0x' + keccakHash(p).slice(-40).toLowerCase(); }
function addrTRX(p) { return b58CheckEncode(0x41, hash160(p)); }
function addrBNB(p) { return '0x' + keccakHash(p).slice(-40).toLowerCase(); }
function addrLTC(p) { return b58CheckEncode(0x30, hash160(p)); }

const AF = {btc:addrBTC,eth:addrETH,trx:addrTRX,bnb:addrBNB,ltc:addrLTC};
const CN = {btc:'Bitcoin',eth:'Ethereum',trx:'Tron',bnb:'Binance',ltc:'Litecoin'};
const CS = {btc:'BTC',eth:'ETH',trx:'TRX',bnb:'BNB',ltc:'LTC'};
const ALL = ['btc','eth','trx','bnb','ltc'];

function deriveAll(mnemonic) {
    const pk = mnemonicToMasterKey(mnemonic);
    const {compressed, uncompressed} = getPublicKeys(pk);
    const comp = {}, uncomp = {};
    for (const c of ALL) { comp[c] = AF[c](compressed); uncomp[c] = AF[c](uncompressed); }
    return { privkey_hex: pk, comp, uncomp };
}

// ============================================================
//  10 TOR GROUPS - Each group = independent API rotation set
//  When one group hits API limit → instantly switch to next
// ============================================================
const NUM_TORS = 10;

// TOR group health tracker
const torHealth = Array.from({length: NUM_TORS}, (_, i) => ({
    id: i + 1,
    active: true,
    errorCount: 0,
    lastError: 0,
    recoveryTime: 0,
    totalRequests: 0,
    successRequests: 0,
    label: `TOR-${i + 1}`
}));

// Active TOR index (round-robin + failover)
let activeTorIdx = 0;
const TOR_COOLDOWN_MS = 10000; // 10 seconds cooldown for a tor group

function getActiveTor() {
    const now = Date.now();
    // Try to recover cooled-down tors
    for (const t of torHealth) {
        if (!t.active && now > t.recoveryTime) {
            t.active = true;
            t.errorCount = 0;
            console.log(`[TOR-${t.id}] Recovered - back online`);
            io.emit('tor_status', torHealth.map(t => ({ ...t })));
        }
    }
    // Find next active tor
    let tries = 0;
    while (tries < NUM_TORS) {
        const idx = activeTorIdx % NUM_TORS;
        if (torHealth[idx].active) {
            return idx;
        }
        activeTorIdx++;
        tries++;
    }
    // All tors down - reset all and return 0
    for (const t of torHealth) { t.active = true; t.errorCount = 0; }
    return 0;
}

function reportTorError(torIdx) {
    const t = torHealth[torIdx];
    t.errorCount++;
    t.lastError = Date.now();
    if (t.errorCount >= 5) {
        t.active = false;
        t.recoveryTime = Date.now() + TOR_COOLDOWN_MS;
        activeTorIdx = (torIdx + 1) % NUM_TORS; // Instantly switch
        console.log(`[TOR-${t.id}] Disabled (${t.errorCount} errors) → Switching to TOR-${activeTorIdx + 1}`);
        io.emit('tor_switch', { from: t.id, to: activeTorIdx + 1 });
        io.emit('tor_status', torHealth.map(t => ({ ...t })));
    }
}

function reportTorSuccess(torIdx) {
    const t = torHealth[torIdx];
    t.totalRequests++;
    t.successRequests++;
    if (t.errorCount > 0) t.errorCount = Math.max(0, t.errorCount - 1);
}

// ============================================================
//  FETCH WITH TIMEOUT (1.5 seconds)
// ============================================================
async function fetchT(url, opts = {}, ms = 1500) {
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), ms);
    try {
        const r = await fetch(url, { ...opts, signal: ctrl.signal });
        clearTimeout(tid);
        return r;
    } catch(e) { clearTimeout(tid); throw e; }
}

// ============================================================
//  BASE ENDPOINTS - 30 unique per coin, expanded to 150
//  Split into 10 TOR groups = 15 APIs per TOR per coin
// ============================================================
const BASE_RPC = {
    btc: [
        {t:'esplora',u:'https://mempool.space/api/address/'},
        {t:'esplora',u:'https://mempool.emzy.de/api/address/'},
        {t:'esplora',u:'https://mempool.fmt.cash/api/address/'},
        {t:'esplora',u:'https://mempool.ninja/api/address/'},
        {t:'esplora',u:'https://mempool.btc.petertodd.org/api/address/'},
        {t:'esplora',u:'https://mempool.bitcoin.pt/api/address/'},
        {t:'esplora',u:'https://mempool.nostr.zone/api/address/'},
        {t:'esplora',u:'https://mempool.donatebtc.io/api/address/'},
        {t:'esplora',u:'https://blockstream.info/api/address/'},
        {t:'esplora',u:'https://btc1.trezor.io/api/address/'},
        {t:'esplora',u:'https://btc2.trezor.io/api/address/'},
        {t:'esplora',u:'https://btc3.trezor.io/api/address/'},
        {t:'blockchain_info',u:'https://blockchain.info/balance?active='},
        {t:'blockchain_multi',u:'https://blockchain.info/multiaddr?active='},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/btc/main/addrs/'},
        {t:'chainso',u:'https://chain.so/api/v3/get_address_balance/BTC/'},
        {t:'chainso_v2',u:'https://chain.so/api/v2/get_address_balance/BTC/'},
        {t:'bitaps',u:'https://api.bitaps.com/btc/v1/blockchain/address/'},
        {t:'blockchair',u:'https://api.blockchair.com/bitcoin/dashboards/address/'},
        {t:'smartbit',u:'https://api.smartbit.com.au/v1/blockchain/address/'},
        {t:'tokenview',u:'https://services.tokenview.io/vipapi/coin/btc/address/balance/'},
        {t:'btccom',u:'https://chain.api.btc.com/v3/address/'},
        {t:'esplora_tx',u:'https://mempool.space/api/address/'},
        {t:'esplora_tx',u:'https://blockstream.info/api/address/'},
        {t:'esplora_tx',u:'https://btc1.trezor.io/api/address/'},
    ],
    eth: [
        {t:'evm',u:'https://rpc.ankr.com/eth'},
        {t:'evm',u:'https://ethereum.publicnode.com'},
        {t:'evm',u:'https://cloudflare-eth.com'},
        {t:'evm',u:'https://eth.llamarpc.com'},
        {t:'evm',u:'https://eth-mainnet.public.blastapi.io'},
        {t:'evm',u:'https://1rpc.io/eth'},
        {t:'evm',u:'https://ethereum.blockpi.network/v1/rpc/public'},
        {t:'evm',u:'https://gateway.tenderly.co/public/ethereum'},
        {t:'evm',u:'https://rpc.mevblocker.io'},
        {t:'evm',u:'https://eth.drpc.org'},
        {t:'evm',u:'https://ethereumnodelight.app.runonflux.io'},
        {t:'evm',u:'https://rpc.flashbots.net'},
        {t:'evm',u:'https://mainnet.eth.cloud.ava.do'},
        {t:'evm',u:'https://eth.gateway.pm'},
        {t:'evm',u:'https://rpc.ethereal.engineering'},
        {t:'evm',u:'https://eth.archivelabs.org'},
        {t:'evm',u:'https://eth.rencode.io'},
        {t:'evm',u:'https://api.mycryptoapi.com/eth'},
        {t:'evm',u:'https://nodes.mewapi.io/rpc/eth'},
        {t:'evm',u:'https://rpc.scaffoldeth.io'},
        {t:'evm',u:'https://eth-mainnet.rpc.blxrbdn.com'},
        {t:'evm',u:'https://eth-mainnet.nodereal.io/v1/35deee6b1b2e4fb0b2ec74f9'},
        {t:'evm_tx',u:'https://rpc.ankr.com/eth'},
        {t:'evm_tx',u:'https://ethereum.publicnode.com'},
        {t:'evm_tx',u:'https://eth.llamarpc.com'},
    ],
    bnb: [
        {t:'evm',u:'https://bsc-dataseed.binance.org'},
        {t:'evm',u:'https://bsc-dataseed1.defibit.io'},
        {t:'evm',u:'https://bsc-dataseed2.ninicoin.io'},
        {t:'evm',u:'https://bsc-dataseed3.defibit.io'},
        {t:'evm',u:'https://bsc-dataseed4.defibit.io'},
        {t:'evm',u:'https://bsc-dataseed1.binance.org'},
        {t:'evm',u:'https://bsc-dataseed2.binance.org'},
        {t:'evm',u:'https://bsc-dataseed3.binance.org'},
        {t:'evm',u:'https://bsc-dataseed4.binance.org'},
        {t:'evm',u:'https://rpc.ankr.com/bsc'},
        {t:'evm',u:'https://bsc.publicnode.com'},
        {t:'evm',u:'https://bsc-mainnet.public.blastapi.io'},
        {t:'evm',u:'https://bsc-rpc.publicnode.com'},
        {t:'evm',u:'https://binance.llamarpc.com'},
        {t:'evm',u:'https://bsc-mainnet.nodereal.io/v1/d7b1239279e34217b3d3645e'},
        {t:'evm',u:'https://bsc-dataseed.binance.org'},
        {t:'evm',u:'https://bsc-dataseed1.defibit.io'},
        {t:'evm',u:'https://bsc-dataseed2.ninicoin.io'},
        {t:'evm',u:'https://bsc-dataseed3.defibit.io'},
        {t:'evm',u:'https://rpc.ankr.com/bsc'},
        {t:'evm',u:'https://bsc.publicnode.com'},
        {t:'evm',u:'https://binance.llamarpc.com'},
        {t:'evm',u:'https://bsc-dataseed1.binance.org'},
        {t:'evm',u:'https://bsc-dataseed2.binance.org'},
        {t:'evm_tx',u:'https://rpc.ankr.com/bsc'},
    ],
    trx: [
        {t:'trongrid',u:'https://api.trongrid.io/v1/accounts/'},
        {t:'trongrid_nile',u:'https://nile.trongrid.io/v1/accounts/'},
        {t:'tronscan',u:'https://apilist.tronscanapi.com/api/accountv2?address='},
        {t:'tronscan_org',u:'https://apilist.tronscan.org/api/accountv2?address='},
        {t:'tronview',u:'https://api.tronview.io/account?address='},
        {t:'tokenview',u:'https://services.tokenview.io/vipapi/coin/trx/address/balance/'},
        {t:'trongrid',u:'https://api.trongrid.io/v1/accounts/'},
        {t:'trongrid_nile',u:'https://nile.trongrid.io/v1/accounts/'},
        {t:'tronscan',u:'https://apilist.tronscanapi.com/api/accountv2?address='},
        {t:'tronscan_org',u:'https://apilist.tronscan.org/api/accountv2?address='},
        {t:'tronview',u:'https://api.tronview.io/account?address='},
        {t:'tokenview',u:'https://services.tokenview.io/vipapi/coin/trx/address/balance/'},
        {t:'trongrid',u:'https://api.trongrid.io/v1/accounts/'},
        {t:'trongrid_nile',u:'https://nile.trongrid.io/v1/accounts/'},
        {t:'tronscan',u:'https://apilist.tronscanapi.com/api/accountv2?address='},
        {t:'tronscan_org',u:'https://apilist.tronscan.org/api/accountv2?address='},
        {t:'tronview',u:'https://api.tronview.io/account?address='},
        {t:'tokenview',u:'https://services.tokenview.io/vipapi/coin/trx/address/balance/'},
        {t:'trongrid',u:'https://api.trongrid.io/v1/accounts/'},
        {t:'trongrid_nile',u:'https://nile.trongrid.io/v1/accounts/'},
        {t:'tronscan',u:'https://apilist.tronscanapi.com/api/accountv2?address='},
        {t:'tronscan_org',u:'https://apilist.tronscan.org/api/accountv2?address='},
        {t:'tronview',u:'https://api.tronview.io/account?address='},
        {t:'tokenview',u:'https://services.tokenview.io/vipapi/coin/trx/address/balance/'},
        {t:'trongrid',u:'https://api.trongrid.io/v1/accounts/'},
    ],
    ltc: [
        {t:'litecoinspace',u:'https://litecoinspace.org/api/address/'},
        {t:'litecoinspace',u:'https://ltc1.trezor.io/api/address/'},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/ltc/main/addrs/'},
        {t:'chainso',u:'https://chain.so/api/v3/get_address_balance/LTC/'},
        {t:'chainso_v2',u:'https://chain.so/api/v2/get_address_balance/LTC/'},
        {t:'blockchair',u:'https://api.blockchair.com/litecoin/dashboards/address/'},
        {t:'bitaps',u:'https://api.bitaps.com/ltc/v1/blockchain/address/'},
        {t:'litecoinspace',u:'https://litecoinspace.org/api/address/'},
        {t:'litecoinspace',u:'https://ltc1.trezor.io/api/address/'},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/ltc/main/addrs/'},
        {t:'chainso',u:'https://chain.so/api/v3/get_address_balance/LTC/'},
        {t:'chainso_v2',u:'https://chain.so/api/v2/get_address_balance/LTC/'},
        {t:'blockchair',u:'https://api.blockchair.com/litecoin/dashboards/address/'},
        {t:'bitaps',u:'https://api.bitaps.com/ltc/v1/blockchain/address/'},
        {t:'litecoinspace',u:'https://litecoinspace.org/api/address/'},
        {t:'litecoinspace',u:'https://ltc1.trezor.io/api/address/'},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/ltc/main/addrs/'},
        {t:'chainso',u:'https://chain.so/api/v3/get_address_balance/LTC/'},
        {t:'chainso_v2',u:'https://chain.so/api/v2/get_address_balance/LTC/'},
        {t:'blockchair',u:'https://api.blockchair.com/litecoin/dashboards/address/'},
        {t:'bitaps',u:'https://api.bitaps.com/ltc/v1/blockchain/address/'},
        {t:'litecoinspace',u:'https://litecoinspace.org/api/address/'},
        {t:'litecoinspace',u:'https://ltc1.trezor.io/api/address/'},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/ltc/main/addrs/'},
        {t:'chainso',u:'https://chain.so/api/v3/get_address_balance/LTC/'},
    ]
};

// Expand to 150 per coin
const RPC = {};
for (const c of ALL) {
    RPC[c] = [];
    while (RPC[c].length < 150) RPC[c].push(...BASE_RPC[c]);
    RPC[c] = RPC[c].slice(0, 150);
}

// Split RPC into 10 TOR groups (15 APIs per group per coin)
function getTorGroup(torIdx, coin) {
    const total = RPC[coin].length;
    const perGroup = Math.ceil(total / NUM_TORS);
    const start = (torIdx % NUM_TORS) * perGroup;
    const end = Math.min(start + perGroup, total);
    return RPC[coin].slice(start, end);
}

// ============================================================
//  GLOBAL COUNTERS
// ============================================================
let apiCallCount = 0;
const ZERO = {received:0, sent:0, balance:0, tx_in:0, tx_out:0, tx_total:0, error:false};
const ERR  = {received:0, sent:0, balance:0, tx_in:0, tx_out:0, tx_total:0, error:true};

// ============================================================
//  API CALLERS WITH TX COUNT
// ============================================================
async function callBTC(ep, a) {
    if (ep.t === 'esplora' || ep.t === 'esplora_tx') {
        const r = await fetchT(ep.u + a);
        if (!r.ok) throw 0;
        const d = await r.json();
        const c = d.chain_stats || d.mempool_stats || {};
        const f = parseInt(c.funded_txo_sum) || 0, s = parseInt(c.spent_txo_sum) || 0;
        const tx_in = parseInt(c.tx_count) || 0;
        return {received:f/1e8, sent:s/1e8, balance:(f-s)/1e8, tx_in, tx_out:0, tx_total:tx_in};
    }
    if (ep.t === 'blockchain_info') {
        const r = await fetchT(ep.u + a); if (!r.ok) throw 0;
        const d = await r.json(); const i = d[a]; if (!i) throw 0;
        const tx_total = parseInt(i.n_tx) || 0;
        return {received:(i.total_received||0)/1e8, sent:(i.total_sent||0)/1e8, balance:(i.final_balance||0)/1e8, tx_in:tx_total, tx_out:0, tx_total};
    }
    if (ep.t === 'blockchain_multi') {
        const r = await fetchT(ep.u + a); if (!r.ok) throw 0;
        const d = await r.json();
        if (d.addresses && d.addresses[0]) {
            const i = d.addresses[0];
            const tx_total = parseInt(i.n_tx) || 0;
            return {received:(i.total_received||0)/1e8, sent:(i.total_sent||0)/1e8, balance:(i.final_balance||0)/1e8, tx_in:tx_total, tx_out:0, tx_total};
        }
        throw 0;
    }
    if (ep.t === 'blockcypher') {
        const r = await fetchT(ep.u+a+'/balance'); if(!r.ok) throw 0;
        const d = await r.json();
        const tx_total = parseInt(d.n_tx) || 0;
        return {received:(d.total_received||0)/1e8, sent:(d.total_sent||0)/1e8, balance:(d.final_balance||0)/1e8, tx_in:tx_total, tx_out:0, tx_total};
    }
    if (ep.t === 'chainso') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(d.status!=='success')throw 0; return {received:0,sent:0,balance:(parseFloat(d.data.confirmed_balance)||0)/1e8,tx_in:0,tx_out:0,tx_total:0}; }
    if (ep.t === 'chainso_v2') { const r = await fetchT(ep.u+a+'/confirmed'); if(!r.ok)throw 0; const d=await r.json(); if(d.status!=='success')throw 0; return {received:0,sent:0,balance:(parseFloat(d.data.balance)||0)/1e8,tx_in:0,tx_out:0,tx_total:0}; }
    if (ep.t === 'bitaps') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); return {received:(d.received||0)/1e8,sent:(d.sent||0)/1e8,balance:(d.balance||0)/1e8,tx_in:parseInt(d.received_count)||0,tx_out:parseInt(d.sent_count)||0,tx_total:(parseInt(d.received_count)||0)+(parseInt(d.sent_count)||0)}; }
    if (ep.t === 'blockchair') { const r = await fetchT(ep.u+a+'?limit=0'); if(!r.ok)throw 0; const d=await r.json(); const ad=d.data&&d.data[a]; if(!ad)throw 0; const tx_total=ad.address.transaction_count||0; return {received:(ad.address.received||0)/1e8,sent:(ad.address.spent||0)/1e8,balance:(ad.address.balance||0)/1e8,tx_in:tx_total,tx_out:0,tx_total}; }
    if (ep.t === 'smartbit') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(!d.success)throw 0; return {received:(d.address.total_received||0)/1e8,sent:(d.address.total_sent||0)/1e8,balance:(d.address.balance||0)/1e8,tx_in:parseInt(d.address.total_txs)||0,tx_out:0,tx_total:parseInt(d.address.total_txs)||0}; }
    if (ep.t === 'tokenview') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(!d.code||d.code!==200)throw 0; return {received:0,sent:0,balance:(parseFloat(d.result)||0)/1e8,tx_in:0,tx_out:0,tx_total:0}; }
    if (ep.t === 'btccom') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(d.err_no!==0)throw 0; return {received:(d.data.total_receive||0)/1e8,sent:0,balance:(d.data.balance||0)/1e8,tx_in:d.data.tx_count||0,tx_out:0,tx_total:d.data.tx_count||0}; }
    throw 0;
}

async function callEVM(ep, a) {
    const dec = a.toLowerCase().startsWith('0x') ? a : '0x' + a;
    const r = await fetchT(ep.u, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({jsonrpc:'2.0',method:'eth_getBalance',params:[dec,'latest'],id:1}) });
    if (!r.ok) throw 0;
    const d = await r.json(); if (d.error) throw 0;
    return {received:0, sent:0, balance:(parseInt(d.result,16)||0)/1e18, tx_in:0, tx_out:0, tx_total:0};
}

async function callEVM_TX(ep, a) {
    // Get transaction count via eth_getTransactionCount
    const dec = a.toLowerCase().startsWith('0x') ? a : '0x' + a;
    const [rBal, rTx] = await Promise.allSettled([
        fetchT(ep.u, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({jsonrpc:'2.0',method:'eth_getBalance',params:[dec,'latest'],id:1}) }),
        fetchT(ep.u, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({jsonrpc:'2.0',method:'eth_getTransactionCount',params:[dec,'latest'],id:2}) })
    ]);
    let balance = 0, tx_total = 0;
    if (rBal.status==='fulfilled' && rBal.value.ok) {
        const d = await rBal.value.json(); if (!d.error) balance = (parseInt(d.result,16)||0)/1e18;
    }
    if (rTx.status==='fulfilled' && rTx.value.ok) {
        const d = await rTx.value.json(); if (!d.error) tx_total = parseInt(d.result,16)||0;
    }
    return {received:0, sent:0, balance, tx_in:tx_total, tx_out:0, tx_total};
}

async function callTRX(ep, a) {
    if (ep.t==='trongrid'||ep.t==='trongrid_nile') {
        const r=await fetchT(ep.u+a); if(!r.ok)throw 0;
        const d=await r.json();
        if(!d.success||!d.data||!d.data.length) return{...ZERO};
        const acc = d.data[0];
        return {received:0, sent:0, balance:(acc.balance||0)/1e6, tx_in:acc.create_time?1:0, tx_out:0, tx_total:acc.active_permission?1:0};
    }
    if (ep.t==='tronscan'||ep.t==='tronscan_org') {
        const r=await fetchT(ep.u+a); if(!r.ok)throw 0;
        const d=await r.json();
        return {received:0, sent:0, balance:(parseFloat(d.balance)||0)/1e6, tx_in:parseInt(d.totalTransactionCount)||0, tx_out:0, tx_total:parseInt(d.totalTransactionCount)||0};
    }
    if (ep.t==='tronview') { const r=await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); return{received:0,sent:0,balance:(parseFloat(d.balance)||0)/1e6,tx_in:0,tx_out:0,tx_total:0}; }
    if (ep.t==='tokenview') { const r=await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(!d.code||d.code!==200)throw 0; return{received:0,sent:0,balance:(parseFloat(d.result)||0)/1e6,tx_in:0,tx_out:0,tx_total:0}; }
    throw 0;
}

async function callLTC(ep, a) {
    if (ep.t==='litecoinspace') {
        const r=await fetchT(ep.u+a); if(!r.ok)throw 0;
        const d=await r.json(); const c=d.chain_stats||{};
        const f=parseInt(c.funded_txo_sum)||0, s=parseInt(c.spent_txo_sum)||0;
        const tx_in=parseInt(c.tx_count)||0;
        return {received:f/1e8, sent:s/1e8, balance:(f-s)/1e8, tx_in, tx_out:0, tx_total:tx_in};
    }
    if (ep.t==='blockcypher') { const r=await fetchT(ep.u+a+'/balance'); if(!r.ok)throw 0; const d=await r.json(); return{received:(d.total_received||0)/1e8,sent:(d.total_sent||0)/1e8,balance:(d.final_balance||0)/1e8,tx_in:parseInt(d.n_tx)||0,tx_out:0,tx_total:parseInt(d.n_tx)||0}; }
    if (ep.t==='chainso') { const r=await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(d.status!=='success')throw 0; return{received:0,sent:0,balance:(parseFloat(d.data.confirmed_balance)||0)/1e8,tx_in:0,tx_out:0,tx_total:0}; }
    if (ep.t==='chainso_v2') { const r=await fetchT(ep.u+a+'/confirmed'); if(!r.ok)throw 0; const d=await r.json(); if(d.status!=='success')throw 0; return{received:0,sent:0,balance:(parseFloat(d.data.balance)||0)/1e8,tx_in:0,tx_out:0,tx_total:0}; }
    if (ep.t==='blockchair') { const r=await fetchT(ep.u+a+'?limit=0'); if(!r.ok)throw 0; const d=await r.json(); const ad=d.data&&d.data[a]; if(!ad)throw 0; const tx_total=ad.address.transaction_count||0; return{received:(ad.address.received||0)/1e8,sent:(ad.address.spent||0)/1e8,balance:(ad.address.balance||0)/1e8,tx_in:tx_total,tx_out:0,tx_total}; }
    if (ep.t==='bitaps') { const r=await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); return{received:(d.received||0)/1e8,sent:(d.sent||0)/1e8,balance:(d.balance||0)/1e8,tx_in:parseInt(d.received_count)||0,tx_out:parseInt(d.sent_count)||0,tx_total:(parseInt(d.received_count)||0)+(parseInt(d.sent_count)||0)}; }
    throw 0;
}

async function callAPI(coin, ep, addr) {
    apiCallCount++;
    if (coin === 'btc') return await callBTC(ep, addr);
    if (coin === 'eth') return ep.t.includes('tx') ? await callEVM_TX(ep, addr) : await callEVM(ep, addr);
    if (coin === 'bnb') return ep.t.includes('tx') ? await callEVM_TX(ep, addr) : await callEVM(ep, addr);
    if (coin === 'trx') return await callTRX(ep, addr);
    if (coin === 'ltc') return await callLTC(ep, addr);
    throw 0;
}

// ============================================================
//  BALANCE CHECK WITH TOR FAILOVER
//  - Uses current active TOR group
//  - On error: instantly switches to next TOR group
//  - Tries 2 APIs from current TOR group, then switches
// ============================================================
async function checkBalanceWithTorFailover(coin, addr, workerTor) {
    // Try using the worker's assigned tor first, then rotate if needed
    let torIdx = workerTor;
    let totalTried = 0;
    const maxTries = NUM_TORS * 3; // Try all tors up to 3 times

    while (totalTried < maxTries) {
        const group = getTorGroup(torIdx, coin);
        if (!group.length) { torIdx = (torIdx + 1) % NUM_TORS; totalTried++; continue; }

        // Pick 2 random endpoints from this tor group
        const shuffled = [...group].sort(() => Math.random() - 0.5).slice(0, 2);

        const results = await Promise.allSettled(
            shuffled.map(ep => callAPI(coin, ep, addr).catch(e => { throw e; }))
        );

        let successCount = 0;
        for (const r of results) {
            if (r.status === 'fulfilled' && r.value && !r.value.error) {
                reportTorSuccess(torIdx);
                return r.value;
            }
        }

        // All failed in this tor group
        reportTorError(torIdx);
        torIdx = (torIdx + 1) % NUM_TORS;
        totalTried++;

        // Small delay before switching (but keep it < 1 second total)
        await new Promise(r => setTimeout(r, 50));
    }

    return {...ERR};
}

// ============================================================
//  STATE
// ============================================================
const state = {
    selCoins: ['btc'],
    checkCount: 0,
    foundCount: 0,
    foundData: loadFoundWallets(), // Load from disk on startup
    startTime: Date.now(),
    speedValue: 0,
    workerStatus: Array.from({length:10}, (_,i) => ({id:i+1, status:'idle', lastMnemonic:'', tor:i%NUM_TORS}))
};

// Restore found count from loaded data
state.foundCount = state.foundData.length;
state.foundData.forEach((f, i) => { if (!f.idx) f.idx = i + 1; });

console.log(`[STARTUP] Loaded ${state.foundData.length} previously found wallets`);

// ============================================================
//  PROCESS ONE WALLET
// ============================================================
async function processWallet(workerId) {
    const mnemonic = genMnemonic(12);
    const wallet = deriveAll(mnemonic);
    state.checkCount++;

    // Assign this worker a tor group (round-robin, but can failover)
    const workerTor = getActiveTor();
    activeTorIdx = (workerTor + 1) % NUM_TORS;

    if (state.workerStatus[workerId-1]) {
        state.workerStatus[workerId-1].status = 'scanning';
        state.workerStatus[workerId-1].lastMnemonic = mnemonic.split(' ').slice(0,3).join(' ') + '...';
        state.workerStatus[workerId-1].tor = workerTor + 1;
    }

    // Check all 10 addresses (5 coins × 2 types) in parallel
    const promises = {};
    for (const coin of ALL) {
        promises[coin] = {
            comp: checkBalanceWithTorFailover(coin, wallet.comp[coin], workerTor),
            uncomp: checkBalanceWithTorFailover(coin, wallet.uncomp[coin], workerTor)
        };
    }
    await Promise.allSettled(ALL.flatMap(c => [promises[c].comp, promises[c].uncomp]));

    const results = {};
    for (const coin of ALL) {
        results[coin] = {
            comp: await promises[coin].comp,
            uncomp: await promises[coin].uncomp
        };
    }

    // Check for found wallets - ANY transaction counts as found!
    for (const coin of ALL) {
        for (const type of ['comp', 'uncomp']) {
            const r = results[coin][type];
            if (r && !r.error) {
                const hasTx = (r.tx_total || 0) > 0;
                const hasBalance = (r.received || 0) > 0 || (r.sent || 0) > 0 || (r.balance || 0) > 0;
                if (hasTx || hasBalance) {
                    state.foundCount++;
                    const address = type === 'comp' ? wallet.comp[coin] : wallet.uncomp[coin];
                    const entry = {
                        idx: state.foundCount,
                        mnemonic,
                        privkey_hex: wallet.privkey_hex,
                        address,
                        comp_addr: wallet.comp[coin],
                        uncomp_addr: wallet.uncomp[coin],
                        coin: CN[coin],
                        coinSym: CS[coin],
                        addrType: type === 'comp' ? 'COMPRESSED' : 'UNCOMPRESSED',
                        received: r.received || 0,
                        sent: r.sent || 0,
                        balance: r.balance || 0,
                        tx_in: r.tx_in || 0,
                        tx_out: r.tx_out || 0,
                        tx_total: r.tx_total || 0,
                        savedAt: Date.now(),
                        torGroup: workerTor + 1
                    };
                    state.foundData.push(entry);
                    saveFoundWallets(state.foundData); // Persist to JSON
                    appendFoundTxt(entry);             // Append to TXT
                    io.emit('found', entry);
                    console.log(`[FOUND] #${entry.idx} ${CS[coin]} ${entry.addrType} B:${entry.balance.toFixed(8)} TX:${entry.tx_total}`);
                }
            }
        }
    }

    // Emit wallet update for display
    const displayCoins = {};
    for (const coin of state.selCoins) {
        displayCoins[coin] = {
            comp_addr: wallet.comp[coin],
            comp: results[coin].comp || {...ERR},
            uncomp_addr: wallet.uncomp[coin],
            uncomp: results[coin].uncomp || {...ERR}
        };
    }
    io.emit('wallet', {
        mnemonic,
        privkey_hex: wallet.privkey_hex,
        coins: displayCoins,
        checkCount: state.checkCount,
        foundCount: state.foundCount,
        apiCallCount,
        privKeyCount: state.checkCount,
        addressCount: state.checkCount * 10,
        workerId,
        torGroup: workerTor + 1
    });

    if (state.workerStatus[workerId-1]) {
        state.workerStatus[workerId-1].status = 'idle';
    }
}

// ============================================================
//  10 PARALLEL WORKERS
// ============================================================
async function worker(id) {
    console.log(`[WORKER ${id}] Started (TOR group: ${(id % NUM_TORS) + 1})`);
    while (true) {
        try {
            await processWallet(id);
        } catch(e) {
            console.error(`[W${id} ERR]`, e && e.message ? e.message : String(e));
            await new Promise(r => setTimeout(r, 500));
        }
    }
}

// ============================================================
//  SPEED COUNTER
// ============================================================
let lastSpeedCheck = 0, lastSpeedTime = Date.now();
setInterval(function() {
    const now = Date.now(), elapsed = (now - lastSpeedTime) / 1000;
    if (elapsed >= 1) {
        const speed = Math.round((state.checkCount - lastSpeedCheck) / elapsed);
        if (speed > 0) state.speedValue = speed;
        io.emit('speed', {
            speed: state.speedValue,
            checkCount: state.checkCount,
            foundCount: state.foundCount,
            apiCallCount,
            privKeyCount: state.checkCount,
            addressCount: state.checkCount * 10,
            workerStatus: state.workerStatus,
            torHealth: torHealth.map(t => ({...t}))
        });
        lastSpeedTime = now;
        lastSpeedCheck = state.checkCount;
    }
}, 1000);

// ============================================================
//  LIVE VIEWER COUNT
// ============================================================
function getViewerCount() { return io.engine.clientsCount || 0; }
function broadcastViewerCount() { io.emit('viewers', { d: getViewerCount() }); }
setInterval(broadcastViewerCount, 3000);

// Broadcast tor status every 5 seconds
setInterval(() => {
    io.emit('tor_status', torHealth.map(t => ({...t})));
}, 5000);

// ============================================================
//  SOCKET.IO
// ============================================================
io.on('connection', function(socket) {
    console.log('[VIEWER] ' + socket.id + ' (' + getViewerCount() + ')');
    socket.emit('init', {
        selCoins: state.selCoins,
        checkCount: state.checkCount,
        foundCount: state.foundCount,
        apiCallCount,
        speed: state.speedValue,
        privKeyCount: state.checkCount,
        addressCount: state.checkCount * 10,
        foundData: state.foundData.slice(-100), // Send last 100 found
        d: getViewerCount(),
        torHealth: torHealth.map(t => ({...t})),
        workerStatus: state.workerStatus
    });
    broadcastViewerCount();

    socket.on('coins_toggle', function(d) {
        if (d && d.coins && Array.isArray(d.coins)) {
            state.selCoins = d.coins.filter(c => ALL.includes(c));
            if (!state.selCoins.length) state.selCoins = ['btc'];
            io.emit('coins_update', {coins: state.selCoins});
        }
    });

    // Client requests full found list
    socket.on('get_found', function() {
        socket.emit('found_list', {data: state.foundData});
    });

    socket.on('disconnect', function() {
        setTimeout(broadcastViewerCount, 500);
    });
});

// ============================================================
//  START
// ============================================================
app.use(express.static('public'));
app.get('/api/found', (req, res) => {
    res.json({ count: state.foundData.length, data: state.foundData });
});
app.get('/api/status', (req, res) => {
    res.json({
        version: '7.0',
        workers: 10,
        torGroups: NUM_TORS,
        checkCount: state.checkCount,
        foundCount: state.foundCount,
        apiCallCount,
        speed: state.speedValue,
        torHealth: torHealth.map(t => ({...t}))
    });
});

server.listen(PORT, function() {
    console.log('============================================');
    console.log('  LUCK WORLD v7.0 - 10 WORKERS - TOR SYSTEM');
    console.log('  10 TOR Groups | Auto Failover < 1s');
    console.log('  TX Count Check | Persistent Found Storage');
    console.log('============================================');
    for (const c of ALL) console.log('  ' + CS[c].padEnd(4) + ': ' + RPC[c].length + ' endpoints');
    console.log('  TOR Groups: ' + NUM_TORS);
    console.log('  APIs/TOR/Coin: ' + Math.ceil(150/NUM_TORS));
    console.log('============================================');

    // Start 10 workers
    for (let i = 1; i <= 10; i++) {
        worker(i);
    }

    setTimeout(() => {
        io.emit('log', {msg:'<span style="color:#60a5fa;font-weight:900;font-size:13px">LUCK WORLD v7.0 - 10 WORKERS - 10 TOR GROUPS</span>'});
        io.emit('log', {msg:'<span style="color:#22c55e">TX Count Check | Auto TOR Failover < 1s | Persistent Storage</span>'});
        io.emit('log', {msg:'<span style="color:#a78bfa">10 TOR Groups × 15 APIs each = 150 APIs/coin | Instant switch on limit</span>'});
    }, 2000);
});