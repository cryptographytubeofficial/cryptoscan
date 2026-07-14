// ============================================================
//  LUCK WORLD SERVER v3.0
//  ONE event per wallet = addresses + balances together
//  ALL 6 coins check in background, display only selected
//  Found = instant save to file + dashboard
// ============================================================

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const CryptoJS = require('crypto-js');
const elliptic = require('elliptic');
const { keccak_256 } = require('js-sha3');
const fs = require('fs');

const ec = new elliptic.ec('secp256k1');
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET','POST'] } });
const PORT = process.env.PORT || 3000;

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

const BIP39 = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon cape capable capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable encourage end endless endorse enemy energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog folk follow food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment gas gasp gate gather gaze gear gender gene general genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose improve impulse inch include income increase index indicate indoor industry infant inflict inform initial inject inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle junior jury just keen keep key keyboard kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson letter level liberty library license life lift light like limb limit link lion liquid list little live lizard load loan lobster local lock logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin marine market marriage mask mass master match material math matrix matter maximum maze meadow medium meet melt member memory mention menu mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment monitor monkey monster month mood moon moral more morning mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee noodle normal north nose notable nothing notice novel now number nurse nut oak obey object oblige obscure observe obtain ocean odd off offense office often oil okay old olive olympic omit once one onion online only open opera opinion oppose option orange orbit orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent park parody party pass patch path patient patrol pattern pause pave payment peace peanut pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare present pretty prevent price pride primary print priority prison private prize problem process produce profit program project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea search season seat second secret section security seed seek segment select sell seminar senior sense sentence series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since sing siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social sock soda soft solar sold solid solution solve someone song soon sorry sort soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel when where whip whisper wide width wife wild will win window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo".split(" ");

function mulberry32(a) { return function() { a |= 0; a = a + 0x6D2B79F5 | 0; var t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
const _prng = mulberry32(Math.floor(Date.now() / 3600000));
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
function addrDASH(p) { return b58CheckEncode(0x4c, hash160(p)); }

const AF = {btc:addrBTC,eth:addrETH,trx:addrTRX,bnb:addrBNB,ltc:addrLTC,dash:addrDASH};
const CN = {btc:'Bitcoin',eth:'Ethereum',trx:'Tron',bnb:'Binance',ltc:'Litecoin',dash:'Dash'};
const CS = {btc:'BTC',eth:'ETH',trx:'TRX',bnb:'BNB',ltc:'LTC',dash:'DASH'};
const ALL = ['btc','eth','trx','bnb','ltc','dash'];

function deriveAll(mnemonic) {
    const pk = mnemonicToMasterKey(mnemonic);
    const {compressed, uncompressed} = getPublicKeys(pk);
    const comp = {}, uncomp = {};
    for (const c of ALL) { comp[c] = AF[c](compressed); uncomp[c] = AF[c](uncompressed); }
    return { privkey_hex: pk, comp, uncomp };
}

// ============================================================
//  RPC ENDPOINTS
// ============================================================
const RPC = {
    btc: [
        {t:'mempool',u:'https://mempool.space/api/address/'},{t:'mempool',u:'https://mempool.emzy.de/api/address/'},
        {t:'mempool',u:'https://mempool.fmt.cash/api/address/'},{t:'mempool',u:'https://mempool.ninja/api/address/'},
        {t:'mempool',u:'https://mempool.btc.petertodd.org/api/address/'},{t:'mempool',u:'https://mempool.bitcoin.pt/api/address/'},
        {t:'mempool',u:'https://mempool.nostr.zone/api/address/'},{t:'mempool',u:'https://mempool.donatebtc.io/api/address/'},
        {t:'blockstream',u:'https://blockstream.info/api/address/'},{t:'blockchain_info',u:'https://blockchain.info/balance?active='},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/btc/main/addrs/'},{t:'chainso',u:'https://chain.so/api/v3/get_address_balance/BTC/'},
        {t:'btc1trezor',u:'https://btc1.trezor.io/api/address/'},{t:'mempool',u:'https://mempool.space/api/address/'},
        {t:'mempool',u:'https://mempool.emzy.de/api/address/'},{t:'blockstream',u:'https://blockstream.info/api/address/'},
        {t:'blockchain_info',u:'https://blockchain.info/balance?active='},{t:'blockcypher',u:'https://api.blockcypher.com/v1/btc/main/addrs/'},
        {t:'chainso',u:'https://chain.so/api/v3/get_address_balance/BTC/'},{t:'mempool',u:'https://mempool.fmt.cash/api/address/'},
        {t:'mempool',u:'https://mempool.ninja/api/address/'},{t:'mempool',u:'https://mempool.bitcoin.pt/api/address/'},
        {t:'mempool',u:'https://mempool.space/api/address/'},{t:'mempool',u:'https://mempool.emzy.de/api/address/'},
        {t:'mempool',u:'https://mempool.fmt.cash/api/address/'},{t:'mempool',u:'https://mempool.ninja/api/address/'},
        {t:'mempool',u:'https://mempool.bitcoin.pt/api/address/'},{t:'mempool',u:'https://mempool.space/api/address/'},
        {t:'mempool',u:'https://mempool.emzy.de/api/address/'},{t:'mempool',u:'https://mempool.fmt.cash/api/address/'},
        {t:'mempool',u:'https://mempool.ninja/api/address/'},{t:'mempool',u:'https://mempool.bitcoin.pt/api/address/'},
        {t:'mempool',u:'https://mempool.space/api/address/'},{t:'mempool',u:'https://mempool.emzy.de/api/address/'},
        {t:'mempool',u:'https://mempool.fmt.cash/api/address/'},{t:'mempool',u:'https://mempool.ninja/api/address/'},
        {t:'mempool',u:'https://mempool.bitcoin.pt/api/address/'},{t:'mempool',u:'https://mempool.space/api/address/'},
        {t:'mempool',u:'https://mempool.emzy.de/api/address/'},{t:'mempool',u:'https://mempool.fmt.cash/api/address/'},
        {t:'mempool',u:'https://mempool.ninja/api/address/'},{t:'mempool',u:'https://mempool.bitcoin.pt/api/address/'},
        {t:'blockstream',u:'https://blockstream.info/api/address/'},{t:'blockchain_info',u:'https://blockchain.info/balance?active='},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/btc/main/addrs/'},{t:'chainso',u:'https://chain.so/api/v3/get_address_balance/BTC/'},
        {t:'btc1trezor',u:'https://btc1.trezor.io/api/address/'}
    ],
    eth: [
        'https://rpc.ankr.com/eth','https://ethereum.publicnode.com','https://cloudflare-eth.com',
        'https://eth.llamarpc.com','https://eth-mainnet.public.blastapi.io','https://1rpc.io/eth',
        'https://ethereum.blockpi.network/v1/rpc/public','https://gateway.tenderly.co/public/ethereum',
        'https://rpc.mevblocker.io','https://eth.drpc.org','https://ethereumnodelight.app.runonflux.io',
        'https://rpc.flashbots.net','https://mainnet.eth.cloud.ava.do','https://eth.gateway.pm',
        'https://rpc.ethereal.engineering','https://eth.archivelabs.org','https://eth.rencode.io',
        'https://eth-mainnet.gateway.pokt.network/v1/5f345397d19a2a60073471b7',
        'https://api.mycryptoapi.com/eth','https://nodes.mewapi.io/rpc/eth',
        'https://eth-mainnet.gateway.pokt.network/v1/5f345397d19a2a60073471b8',
        'https://rpc.scaffoldeth.io','https://eth-mainnet.rpc.blxrbdn.com',
        'https://rpc.ankr.com/eth','https://ethereum.publicnode.com','https://cloudflare-eth.com',
        'https://eth.llamarpc.com','https://1rpc.io/eth','https://eth.drpc.org',
        'https://rpc.flashbots.net','https://eth.gateway.pm','https://rpc.ethereal.engineering',
        'https://eth.archivelabs.org','https://eth.rencode.io','https://rpc.ankr.com/eth',
        'https://ethereum.publicnode.com','https://cloudflare-eth.com','https://eth.llamarpc.com',
        'https://1rpc.io/eth','https://eth.drpc.org','https://rpc.flashbots.net',
        'https://eth.gateway.pm','https://rpc.ethereal.engineering','https://eth.archivelabs.org',
        'https://eth.rencode.io','https://rpc.ankr.com/eth','https://ethereum.publicnode.com',
        'https://cloudflare-eth.com','https://eth.llamarpc.com','https://1rpc.io/eth',
        'https://eth.drpc.org','https://rpc.flashbots.net','https://eth.gateway.pm'
    ],
    bnb: [
        'https://bsc-dataseed.binance.org','https://bsc-dataseed1.defibit.io','https://bsc-dataseed2.ninicoin.io',
        'https://bsc-dataseed3.defibit.io','https://bsc-dataseed4.defibit.io','https://bsc-dataseed1.binance.org',
        'https://bsc-dataseed2.binance.org','https://bsc-dataseed3.binance.org','https://bsc-dataseed4.binance.org',
        'https://rpc.ankr.com/bsc','https://bsc.publicnode.com','https://bsc-mainnet.public.blastapi.io',
        'https://bsc-rpc.publicnode.com','https://binance.llamarpc.com','https://bsc-dataseed.binance.org',
        'https://bsc-dataseed1.defibit.io','https://bsc-dataseed2.ninicoin.io','https://bsc-dataseed3.defibit.io',
        'https://bsc-dataseed4.defibit.io','https://bsc-dataseed1.binance.org','https://bsc-dataseed2.binance.org',
        'https://bsc-dataseed3.binance.org','https://bsc-dataseed4.binance.org','https://rpc.ankr.com/bsc',
        'https://bsc.publicnode.com','https://bsc-mainnet.public.blastapi.io','https://bsc-rpc.publicnode.com',
        'https://binance.llamarpc.com','https://bsc-dataseed.binance.org','https://bsc-dataseed1.defibit.io',
        'https://bsc-dataseed2.ninicoin.io','https://bsc-dataseed3.defibit.io','https://bsc-dataseed4.defibit.io',
        'https://bsc-dataseed1.binance.org','https://bsc-dataseed2.binance.org','https://bsc-dataseed3.binance.org',
        'https://bsc-dataseed4.binance.org','https://rpc.ankr.com/bsc','https://bsc.publicnode.com',
        'https://bsc-mainnet.public.blastapi.io','https://bsc-rpc.publicnode.com','https://binance.llamarpc.com',
        'https://bsc-dataseed.binance.org','https://bsc-dataseed1.defibit.io','https://bsc-dataseed2.ninicoin.io',
        'https://bsc-dataseed3.defibit.io','https://bsc-dataseed4.defibit.io','https://bsc-dataseed1.binance.org',
        'https://bsc-dataseed2.binance.org','https://bsc-dataseed3.binance.org'
    ],
    trx: [
        {t:'trongrid',u:'https://api.trongrid.io/v1/accounts/'},{t:'trongrid2',u:'https://nile.trongrid.io/v1/accounts/'},
        {t:'tronscan',u:'https://apilist.tronscanapi.com/api/accountv2?address='},{t:'tronview',u:'https://api.tronview.io/account?address='},
        {t:'tronscan2',u:'https://apilist.tronscan.org/api/accountv2?address='},
        {t:'trongrid',u:'https://api.trongrid.io/v1/accounts/'},{t:'trongrid2',u:'https://nile.trongrid.io/v1/accounts/'},
        {t:'tronscan',u:'https://apilist.tronscanapi.com/api/accountv2?address='},{t:'tronview',u:'https://api.tronview.io/account?address='},
        {t:'tronscan2',u:'https://apilist.tronscan.org/api/accountv2?address='},
        {t:'trongrid',u:'https://api.trongrid.io/v1/accounts/'},{t:'trongrid2',u:'https://nile.trongrid.io/v1/accounts/'},
        {t:'tronscan',u:'https://apilist.tronscanapi.com/api/accountv2?address='},{t:'tronview',u:'https://api.tronview.io/account?address='},
        {t:'tronscan2',u:'https://apilist.tronscan.org/api/accountv2?address='},
        {t:'trongrid',u:'https://api.trongrid.io/v1/accounts/'},{t:'trongrid2',u:'https://nile.trongrid.io/v1/accounts/'},
        {t:'tronscan',u:'https://apilist.tronscanapi.com/api/accountv2?address='},{t:'tronview',u:'https://api.tronview.io/account?address='},
        {t:'tronscan2',u:'https://apilist.tronscan.org/api/accountv2?address='},
        {t:'trongrid',u:'https://api.trongrid.io/v1/accounts/'},{t:'trongrid2',u:'https://nile.trongrid.io/v1/accounts/'},
        {t:'tronscan',u:'https://apilist.tronscanapi.com/api/accountv2?address='},{t:'tronview',u:'https://api.tronview.io/account?address='}
    ],
    ltc: [
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/ltc/main/addrs/'},{t:'chainso',u:'https://chain.so/api/v3/get_address_balance/LTC/'},
        {t:'litecoinspace',u:'https://litecoinspace.org/api/address/'},{t:'chainso2',u:'https://chain.so/api/v2/get_address_balance/LTC/'},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/ltc/main/addrs/'},{t:'chainso',u:'https://chain.so/api/v3/get_address_balance/LTC/'},
        {t:'litecoinspace',u:'https://litecoinspace.org/api/address/'},{t:'chainso2',u:'https://chain.so/api/v2/get_address_balance/LTC/'},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/ltc/main/addrs/'},{t:'chainso',u:'https://chain.so/api/v3/get_address_balance/LTC/'},
        {t:'litecoinspace',u:'https://litecoinspace.org/api/address/'},{t:'chainso2',u:'https://chain.so/api/v2/get_address_balance/LTC/'},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/ltc/main/addrs/'},{t:'chainso',u:'https://chain.so/api/v3/get_address_balance/LTC/'},
        {t:'litecoinspace',u:'https://litecoinspace.org/api/address/'},{t:'chainso2',u:'https://chain.so/api/v2/get_address_balance/LTC/'},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/ltc/main/addrs/'},{t:'chainso',u:'https://chain.so/api/v3/get_address_balance/LTC/'},
        {t:'litecoinspace',u:'https://litecoinspace.org/api/address/'},{t:'chainso2',u:'https://chain.so/api/v2/get_address_balance/LTC/'},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/ltc/main/addrs/'},{t:'chainso',u:'https://chain.so/api/v3/get_address_balance/LTC/'}
    ],
    dash: [
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/dash/main/addrs/'},{t:'chainso',u:'https://chain.so/api/v3/get_address_balance/DASH/'},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/dash/main/addrs/'},{t:'chainso',u:'https://chain.so/api/v2/get_address_balance/DASH/'},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/dash/main/addrs/'},{t:'chainso',u:'https://chain.so/api/v3/get_address_balance/DASH/'},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/dash/main/addrs/'},{t:'chainso',u:'https://chain.so/api/v2/get_address_balance/DASH/'},
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/dash/main/addrs/'},{t:'chainso',u:'https://chain.so/api/v3/get_address_balance/DASH/'}
    ]
};

let rpcIdx = {}; for (let c of ALL) rpcIdx[c] = 0;
function nextRPC(coin) { const e = RPC[coin]; if (!e||!e.length) return null; const i = rpcIdx[coin]++ % e.length; return e[i]; }
let apiCallCount = 0;

async function checkBalance(coin, addr) {
    const eps = RPC[coin]; if (!eps||!eps.length) return {received:0,sent:0,balance:0,error:true};
    for (let i = 0; i < 10; i++) {
        const ep = nextRPC(coin);
        try {
            apiCallCount++;
            let r;
            if (coin==='btc') r = await chkBTC(ep,addr);
            else if (coin==='eth'||coin==='bnb') r = await chkEVM(ep,addr);
            else if (coin==='trx') r = await chkTRX(ep,addr);
            else r = await chkUTXO(ep,coin,addr);
            if (r && !r.error) return r;
        } catch(e) { continue; }
    }
    return {received:0,sent:0,balance:0,error:true};
}

async function chkBTC(ep,a) {
    if (ep.t==='blockchain_info'){const r=await fetch(ep.u+a);if(!r.ok)throw 0;const d=await r.json();const i=d[a];if(!i)throw 0;return{received:(i.total_received||0)/1e8,sent:(i.total_sent||0)/1e8,balance:(i.final_balance||0)/1e8};}
    if (ep.t==='mempool'||ep.t==='blockstream'||ep.t==='btc1trezor'){const r=await fetch(ep.u+a);if(!r.ok)throw 0;const d=await r.json();const c=d.chain_stats||{};const f=parseInt(c.funded_txo_sum)||0,s=parseInt(c.spent_txo_sum)||0;return{received:f/1e8,sent:s/1e8,balance:(f-s)/1e8};}
    if (ep.t==='blockcypher'){const r=await fetch(ep.u+a+'/balance');if(!r.ok)throw 0;const d=await r.json();return{received:(d.total_received||0)/1e8,sent:(d.total_sent||0)/1e8,balance:(d.final_balance||0)/1e8};}
    if (ep.t==='chainso'||ep.t==='chainso2'){const r=await fetch(ep.u+a);if(!r.ok)throw 0;const d=await r.json();if(d.status!=='success')throw 0;return{received:0,sent:0,balance:(parseFloat(d.data.confirmed_balance)||0)/1e8};}
    throw 0;
}
async function chkEVM(u,a){const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',method:'eth_getBalance',params:[a,'latest'],id:1})});if(!r.ok)throw 0;const d=await r.json();if(d.error)throw 0;return{received:0,sent:0,balance:(parseInt(d.result,16)||0)/1e18};}
async function chkTRX(ep,a){
    if(ep.t==='trongrid'||ep.t==='trongrid2'){const r=await fetch(ep.u+a);if(!r.ok)throw 0;const d=await r.json();if(!d.success||!d.data||!d.data.length)return{received:0,sent:0,balance:0};return{received:0,sent:0,balance:(d.data[0].balance||0)/1e6};}
    if(ep.t==='tronscan'||ep.t==='tronscan2'){const r=await fetch(ep.u+a);if(!r.ok)throw 0;const d=await r.json();return{received:0,sent:0,balance:(parseFloat(d.balance)||0)/1e6};}
    if(ep.t==='tronview'){const r=await fetch(ep.u+a);if(!r.ok)throw 0;const d=await r.json();return{received:0,sent:0,balance:(parseFloat(d.balance)||0)/1e6};}
    throw 0;
}
async function chkUTXO(ep,coin,a){
    if(ep.t==='blockcypher'||ep.t==='blockcypher2'){const r=await fetch(ep.u+a+'/balance');if(!r.ok)throw 0;const d=await r.json();return{received:(d.total_received||0)/1e8,sent:(d.total_sent||0)/1e8,balance:(d.final_balance||0)/1e8};}
    if(ep.t==='chainso'||ep.t==='chainso2'){const r=await fetch(ep.u+a);if(!r.ok)throw 0;const d=await r.json();if(d.status!=='success')throw 0;return{received:0,sent:0,balance:(parseFloat(d.data.confirmed_balance)||0)/1e8};}
    if(ep.t==='litecoinspace'||ep.t==='litecoinspace2'){const r=await fetch(ep.u+a);if(!r.ok)throw 0;const d=await r.json();const c=d.chain_stats||{};const f=parseInt(c.funded_txo_sum)||0,s=parseInt(c.spent_txo_sum)||0;return{received:f/1e8,sent:s/1e8,balance:(f-s)/1e8};}
    throw 0;
}

// ============================================================
//  STATE
// ============================================================
const state = { selCoins: ['btc'], checkCount: 0, foundCount: 0, foundData: [], startTime: Date.now(), lastSpeed: Date.now(), lastCheck: 0 };

// Save found to file permanently
function saveFound(entry) {
    const line = 'MNEMONIC: '+entry.mnemonic+'\nPRIV KEY: '+entry.privkey_hex+'\nCOIN: '+entry.coin+' ('+entry.coinSym+')\nTYPE: '+entry.addrType+'\nCOMP: '+entry.comp_addr+'\nUNCOMP: '+(entry.uncomp_addr||'N/A')+'\nR:'+entry.received.toFixed(8)+' S:'+entry.sent.toFixed(8)+' B:'+entry.balance.toFixed(8)+' '+entry.coinSym+'\nDATE: '+new Date().toISOString()+'\n'+'='.repeat(60)+'\n\n';
    fs.appendFileSync('found_wallets.txt', line);
}

// ============================================================
//  SCANNER v3 - Complete block per wallet
// ============================================================
async function scanOne() {
    const mnemonic = genMnemonic(12);
    const wallet = deriveAll(mnemonic);
    state.checkCount++;

    // Check ALL 12 addresses concurrently
    const results = {};
    const checks = [];
    for (const coin of ALL) {
        results[coin] = {};
        checks.push(checkBalance(coin, wallet.comp[coin]).then(r => { results[coin].comp = r; }).catch(() => { results[coin].comp = {error:true,received:0,sent:0,balance:0}; }));
        checks.push(checkBalance(coin, wallet.uncomp[coin]).then(r => { results[coin].uncomp = r; }).catch(() => { results[coin].uncomp = {error:true,received:0,sent:0,balance:0}; }));
    }
    await Promise.allSettled(checks);

    // Check FOUND for ALL coins (background - even non-selected)
    for (const coin of ALL) {
        const cr = results[coin];
        ['comp','uncomp'].forEach(type => {
            const r = cr[type];
            if (r && !r.error && ((r.received||0) > 0 || (r.sent||0) > 0 || (r.balance||0) > 0)) {
                state.foundCount++;
                const entry = {
                    idx: state.foundCount, mnemonic, privkey_hex: wallet.privkey_hex,
                    comp_addr: wallet.comp[coin], uncomp_addr: wallet.uncomp[coin],
                    coin: CN[coin], coinSym: CS[coin], addrType: type === 'comp' ? 'COMPRESSED' : 'UNCOMPRESSED',
                    received: r.received, sent: r.sent, balance: r.balance
                };
                state.foundData.push(entry);
                saveFound(entry);
                io.emit('found', entry);
                console.log('[FOUND] #' + entry.idx + ' ' + CS[coin] + ' ' + entry.addrType + ' B:' + entry.balance.toFixed(8));
            }
        });
    }

    // Build display data for SELECTED coins only
    const displayCoins = {};
    for (const coin of state.selCoins) {
        const cr = results[coin] || {};
        displayCoins[coin] = {
            comp_addr: wallet.comp[coin],
            comp: cr.comp || {error:true,received:0,sent:0,balance:0},
            uncomp_addr: wallet.uncomp[coin],
            uncomp: cr.uncomp || {error:true,received:0,sent:0,balance:0}
        };
    }

    // Emit ONE complete event
    io.emit('wallet', {
        mnemonic, privkey_hex: wallet.privkey_hex,
        coins: displayCoins,
        checkCount: state.checkCount, foundCount: state.foundCount, apiCallCount
    });

    // Speed
    const now = Date.now();
    if (now - state.lastSpeed >= 1000) {
        const speed = Math.round((state.checkCount - state.lastCheck) / ((now - state.lastSpeed) / 1000));
        io.emit('speed', { speed, checkCount: state.checkCount, foundCount: state.foundCount, apiCallCount });
        state.lastSpeed = now; state.lastCheck = state.checkCount;
    }
}

async function runScanner() {
    console.log('[LUCK WORLD v3.0] Scanner started - complete block per wallet');
    const total = Object.values(RPC).reduce((s,e) => s+e.length, 0);
    console.log('[LUCK WORLD] ' + total + ' RPC endpoints');
    io.emit('log', { msg: '<span class="lb" style="font-weight:900;font-size:12px">LUCK WORLD v3.0 - LIVE SERVER</span>' });
    io.emit('log', { msg: '<span class="lg">Address + Balance = One Block</span>' });
    io.emit('log', { msg: '<span class="lc">Background: ALL 6 coins x 2 types checked</span>' });
    io.emit('log', { msg: '' });
    while (true) { try { await scanOne(); } catch(e) { console.error('[ERR]', e.message); await new Promise(r=>setTimeout(r,1000)); } }
}

// ============================================================
//  SOCKET.IO
// ============================================================
io.on('connection', (socket) => {
    console.log('[VIEWER] ' + socket.id + ' (total: ' + io.engine.clientsCount + ')');
    socket.emit('init', { selCoins: state.selCoins, checkCount: state.checkCount, foundCount: state.foundCount, apiCallCount, foundData: state.foundData });
    socket.on('coins_toggle', (d) => {
        if (d && d.coins && Array.isArray(d.coins)) {
            state.selCoins = d.coins.filter(c => ALL.includes(c));
            if (!state.selCoins.length) state.selCoins = ['btc'];
            console.log('[COINS] ' + state.selCoins.join(', '));
            io.emit('coins_update', { coins: state.selCoins });
        }
    });
    socket.on('disconnect', () => { console.log('[DISC] ' + socket.id); });
});

app.use(express.static('public'));
server.listen(PORT, () => {
    console.log('============================================');
    console.log('  LUCK WORLD v3.0 - Complete Block');
    console.log('  Port: ' + PORT);
    console.log('============================================');
    runScanner();
});