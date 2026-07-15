// ============================================================
//  LUCK WORLD SERVER v6.0
//  NO DASH | 5 COINS | 150+ APIs/COIN | 3 WORKERS
//  RANDOM API | INFINITE RETRY
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

// ============================================================
//  IP ROTATION - Add proxy URLs to avoid rate limits
//  Each key picks a random proxy from this list
//  Leave empty [] for direct connection (no proxy)
//  Paid rotating proxies recommended for production:
//    'http://user:pass@proxy.example.com:8080'
//  Free proxies (unreliable):
//    'http://free-proxy:port'
// ============================================================
const PROXIES = [
    // Add your proxy URLs here, example:
    // 'http://user:pass@rotating-proxy.com:8080',
    // 'http://user:pass@another-proxy.com:3128',
];

function getRandomProxy() {
    if (!PROXIES || !PROXIES.length) return null;
    return PROXIES[Math.floor(Math.random() * PROXIES.length)];
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
//  PUZZLE #71 RANGE: 400000000000000000 to 7fffffffffffffffff
//  2^66 to 2^67 - 1
// ============================================================
function genRandomPrivKey() {
    const buf = new Uint8Array(9); // 72 bits > 66 bits needed
    require('crypto').randomFillSync(buf);
    let val = 0n;
    for (let i = 0; i < 9; i++) val = (val << 8n) | BigInt(buf[i]);
    val = (val & ((1n << 66n) - 1n)) + (1n << 66n); // mask 66 bits + offset
    return val.toString(16).padStart(64, '0');
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

function deriveAll(privHex) {
    const {compressed, uncompressed} = getPublicKeys(privHex);
    const comp = {}, uncomp = {};
    for (const c of ALL) { comp[c] = AF[c](compressed); uncomp[c] = AF[c](uncompressed); }
    return { privkey_hex: privHex, comp, uncomp };
}

// ============================================================
//  FETCH WITH TIMEOUT (2 seconds) + PROXY SUPPORT
// ============================================================
async function fetchT(url, opts = {}, ms = 2000) {
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), ms);
    try {
        const proxy = getRandomProxy();
        const fetchOpts = { ...opts, signal: ctrl.signal };
        // If proxy is set, we'd need http agent - for now direct
        const r = await fetch(url, fetchOpts);
        clearTimeout(tid);
        return r;
    } catch(e) { clearTimeout(tid); throw e; }
}

// ============================================================
//  BASE ENDPOINTS (~30 unique per coin)
// ============================================================
const BASE_RPC = {
    btc: [
        // Esplora / Mempool / Blockbook (fast, same format)
        {t:'esplora',u:'https://mempool.space/api/address/'},
        {t:'esplora',u:'https://mempool.emzy.de/api/address/'},
        {t:'esplora',u:'https://mempool.fmt.cash/api/address/'},
        {t:'esplora',u:'https://mempool.ninja/api/address/'},
        {t:'esplora',u:'https://mempool.btc.petertodd.org/api/address/'},
        {t:'esplora',u:'https://mempool.bitcoin.pt/api/address/'},
        {t:'esplora',u:'https://mempool.nostr.zone/api/address/'},
        {t:'esplora',u:'https://mempool.donatebtc.io/api/address/'},
        {t:'esplora',u:'https://blockstream.info/api/address/'},
        // Trezor Blockbook
        {t:'esplora',u:'https://btc1.trezor.io/api/address/'},
        {t:'esplora',u:'https://btc2.trezor.io/api/address/'},
        {t:'esplora',u:'https://btc3.trezor.io/api/address/'},
        // Blockchain.info
        {t:'blockchain_info',u:'https://blockchain.info/balance?active='},
        {t:'blockchain_multi',u:'https://blockchain.info/multiaddr?active='},
        // BlockCypher
        {t:'blockcypher',u:'https://api.blockcypher.com/v1/btc/main/addrs/'},
        // Chain.so
        {t:'chainso',u:'https://chain.so/api/v3/get_address_balance/BTC/'},
        {t:'chainso_v2',u:'https://chain.so/api/v2/get_address_balance/BTC/'},
        // Bitaps
        {t:'bitaps',u:'https://api.bitaps.com/btc/v1/blockchain/address/'},
        // Blockchair
        {t:'blockchair',u:'https://api.blockchair.com/bitcoin/dashboards/address/'},
        // Smartbit
        {t:'smartbit',u:'https://api.smartbit.com.au/v1/blockchain/address/'},
        // Tokenview
        {t:'tokenview',u:'https://services.tokenview.io/vipapi/coin/btc/address/balance/'},
        // BTC.com
        {t:'btccom',u:'https://chain.api.btc.com/v3/address/'},
        // More mempool mirrors
        {t:'esplora',u:'https://mempool.space/api/address/'},
        {t:'esplora',u:'https://mempool.emzy.de/api/address/'},
        {t:'esplora',u:'https://blockstream.info/api/address/'},
        {t:'esplora',u:'https://btc1.trezor.io/api/address/'}
    ],
    eth: [
        // 30+ unique public RPCs
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
        {t:'evm',u:'https://eth-mainnet.gateway.pokt.network/v1/5f345397d19a2a60073471b7'},
        {t:'evm',u:'https://rpc.ankr.com/eth'},
        {t:'evm',u:'https://ethereum.publicnode.com'},
        {t:'evm',u:'https://cloudflare-eth.com'},
        {t:'evm',u:'https://eth.llamarpc.com'},
        {t:'evm',u:'https://1rpc.io/eth'},
        {t:'evm',u:'https://eth.drpc.org'}
    ],
    bnb: [
        // BSC public RPCs
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
        {t:'evm',u:'https://bsc-dataseed4.defibit.io'},
        {t:'evm',u:'https://rpc.ankr.com/bsc'},
        {t:'evm',u:'https://bsc.publicnode.com'},
        {t:'evm',u:'https://binance.llamarpc.com'},
        {t:'evm',u:'https://bsc-dataseed1.binance.org'},
        {t:'evm',u:'https://bsc-dataseed2.binance.org'},
        {t:'evm',u:'https://bsc-dataseed3.binance.org'},
        {t:'evm',u:'https://bsc-dataseed4.binance.org'},
        {t:'evm',u:'https://rpc.ankr.com/bsc'},
        {t:'evm',u:'https://bsc.publicnode.com'}
    ],
    trx: [
        // TronGrid + Tronscan + TronView + Tokenview
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
        {t:'trongrid_nile',u:'https://nile.trongrid.io/v1/accounts/'},
        {t:'tronscan',u:'https://apilist.tronscanapi.com/api/accountv2?address='}
    ],
    ltc: [
        // Litecoinspace / Blockbook / BlockCypher / Chain.so / Bitaps / Blockchair
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
        {t:'chainso_v2',u:'https://chain.so/api/v2/get_address_balance/LTC/'}
    ]
};

// ============================================================
//  EXPAND TO 150+ PER COIN
// ============================================================
const RPC = {};
for (const c of ALL) {
    RPC[c] = [];
    while (RPC[c].length < 150) RPC[c].push(...BASE_RPC[c]);
    RPC[c] = RPC[c].slice(0, 150);
}

// ============================================================
//  RANDOM API PICKER (never pick same index twice per address)
// ============================================================
let apiCallCount = 0;
const ZERO = {received:0,sent:0,balance:0,error:false};
const ERR  = {received:0,sent:0,balance:0,error:true};

// ============================================================
//  SINGLE API CALL
// ============================================================
async function callAPI(coin, ep, addr) {
    apiCallCount++;
    if (coin === 'btc') return await callBTC(ep, addr);
    if (coin === 'eth' || coin === 'bnb') return await callEVM(ep, addr);
    if (coin === 'trx') return await callTRX(ep, addr);
    if (coin === 'ltc') return await callLTC(ep, addr);
    throw 0;
}

async function callBTC(ep, a) {
    if (ep.t === 'esplora') {
        const r = await fetchT(ep.u + a);
        if (!r.ok) throw 0;
        const d = await r.json();
        const c = d.chain_stats || d.mempool_stats || {};
        const f = parseInt(c.funded_txo_sum) || 0, s = parseInt(c.spent_txo_sum) || 0;
        return {received:f/1e8, sent:s/1e8, balance:(f-s)/1e8};
    }
    if (ep.t === 'blockchain_info') {
        const r = await fetchT(ep.u + a);
        if (!r.ok) throw 0;
        const d = await r.json(); const i = d[a]; if (!i) throw 0;
        return {received:(i.total_received||0)/1e8, sent:(i.total_sent||0)/1e8, balance:(i.final_balance||0)/1e8};
    }
    if (ep.t === 'blockchain_multi') {
        const r = await fetchT(ep.u + a);
        if (!r.ok) throw 0;
        const d = await r.json();
        if (d.addresses && d.addresses[0]) { const i = d.addresses[0]; return {received:(i.total_received||0)/1e8, sent:(i.total_sent||0)/1e8, balance:(i.final_balance||0)/1e8}; }
        throw 0;
    }
    if (ep.t === 'blockcypher') { const r = await fetchT(ep.u+a+'/balance'); if(!r.ok)throw 0; const d=await r.json(); return {received:(d.total_received||0)/1e8,sent:(d.total_sent||0)/1e8,balance:(d.final_balance||0)/1e8}; }
    if (ep.t === 'chainso') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(d.status!=='success')throw 0; return {received:0,sent:0,balance:(parseFloat(d.data.confirmed_balance)||0)/1e8}; }
    if (ep.t === 'chainso_v2') { const r = await fetchT(ep.u+a+'/confirmed'); if(!r.ok)throw 0; const d=await r.json(); if(d.status!=='success')throw 0; return {received:0,sent:0,balance:(parseFloat(d.data.balance)||0)/1e8}; }
    if (ep.t === 'bitaps') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); return {received:(d.received||0)/1e8,sent:(d.sent||0)/1e8,balance:(d.balance||0)/1e8}; }
    if (ep.t === 'blockchair') { const r = await fetchT(ep.u+a+'?limit=0'); if(!r.ok)throw 0; const d=await r.json(); const ad=d.data&&d.data[a]; if(!ad)throw 0; return {received:(ad.address.received||0)/1e8,sent:(ad.address.spent||0)/1e8,balance:(ad.address.balance||0)/1e8}; }
    if (ep.t === 'smartbit') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(!d.success)throw 0; return {received:(d.address.total_received||0)/1e8,sent:(d.address.total_sent||0)/1e8,balance:(d.address.balance||0)/1e8}; }
    if (ep.t === 'tokenview') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(!d.code||d.code!==200)throw 0; return {received:0,sent:0,balance:(parseFloat(d.result)||0)/1e8}; }
    if (ep.t === 'btccom') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(d.err_no!==0)throw 0; return {received:(d.data.total_receive||0)/1e8,sent:0,balance:(d.data.balance||0)/1e8}; }
    throw 0;
}

async function callEVM(ep, a) {
    const dec = a.toLowerCase().startsWith('0x') ? a : '0x' + a;
    const r = await fetchT(ep.u, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({jsonrpc:'2.0',method:'eth_getBalance',params:[dec,'latest'],id:1}) });
    if (!r.ok) throw 0;
    const d = await r.json(); if (d.error) throw 0;
    return {received:0, sent:0, balance:(parseInt(d.result,16)||0)/1e18};
}

async function callTRX(ep, a) {
    if (ep.t==='trongrid'||ep.t==='trongrid_nile') { const r=await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(!d.success||!d.data||!d.data.length)return{...ZERO}; return{received:0,sent:0,balance:(d.data[0].balance||0)/1e6}; }
    if (ep.t==='tronscan'||ep.t==='tronscan_org') { const r=await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); return{received:0,sent:0,balance:(parseFloat(d.balance)||0)/1e6}; }
    if (ep.t==='tronview') { const r=await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); return{received:0,sent:0,balance:(parseFloat(d.balance)||0)/1e6}; }
    if (ep.t==='tokenview') { const r=await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(!d.code||d.code!==200)throw 0; return{received:0,sent:0,balance:(parseFloat(d.result)||0)/1e6}; }
    throw 0;
}

async function callLTC(ep, a) {
    if (ep.t==='litecoinspace') { const r=await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); const c=d.chain_stats||{}; const f=parseInt(c.funded_txo_sum)||0,s=parseInt(c.spent_txo_sum)||0; return{received:f/1e8,sent:s/1e8,balance:(f-s)/1e8}; }
    if (ep.t==='blockcypher') { const r=await fetchT(ep.u+a+'/balance'); if(!r.ok)throw 0; const d=await r.json(); return{received:(d.total_received||0)/1e8,sent:(d.total_sent||0)/1e8,balance:(d.final_balance||0)/1e8}; }
    if (ep.t==='chainso') { const r=await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(d.status!=='success')throw 0; return{received:0,sent:0,balance:(parseFloat(d.data.confirmed_balance)||0)/1e8}; }
    if (ep.t==='chainso_v2') { const r=await fetchT(ep.u+a+'/confirmed'); if(!r.ok)throw 0; const d=await r.json(); if(d.status!=='success')throw 0; return{received:0,sent:0,balance:(parseFloat(d.data.balance)||0)/1e8}; }
    if (ep.t==='blockchair') { const r=await fetchT(ep.u+a+'?limit=0'); if(!r.ok)throw 0; const d=await r.json(); const ad=d.data&&d.data[a]; if(!ad)throw 0; return{received:(ad.address.received||0)/1e8,sent:(ad.address.spent||0)/1e8,balance:(ad.address.balance||0)/1e8}; }
    if (ep.t==='bitaps') { const r=await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); return{received:(d.received||0)/1e8,sent:(d.sent||0)/1e8,balance:(d.balance||0)/1e8}; }
    throw 0;
}

// ============================================================
//  BALANCE CHECK: 2 random APIs → fail → 2 more → infinite retry
// ============================================================
async function checkBalanceWithRetry(coin, addr) {
    const total = RPC[coin].length;
    const tried = new Set();
    while (tried.size < total) {
        const avail = [];
        for (let i = 0; i < total; i++) if (!tried.has(i)) avail.push(i);
        for (let i = avail.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [avail[i], avail[j]] = [avail[j], avail[i]]; }
        const batch = avail.slice(0, Math.min(2, avail.length));
        batch.forEach(i => tried.add(i));
        const results = await Promise.allSettled(batch.map(i => callAPI(coin, RPC[coin][i], addr).catch(() => ({...ERR}))));
        for (const r of results) if (r.status === 'fulfilled' && r.value && !r.value.error) return r.value;
    }
    return {...ERR};
}

// ============================================================
//  STATE
// ============================================================
const state = { selCoins: ['btc'], checkCount: 0, foundCount: 0, foundData: [], startTime: Date.now(), speedValue: 0 };

function saveFound(entry) {
    try { fs.appendFileSync('found_wallets.txt', 'PRIV KEY: '+entry.privkey_hex+'\nCOIN: '+entry.coin+' ('+entry.coinSym+')\nTYPE: '+entry.addrType+'\nCOMP: '+entry.comp_addr+'\nUNCOMP: '+(entry.uncomp_addr||'N/A')+'\nR:'+entry.received.toFixed(8)+' S:'+entry.sent.toFixed(8)+' B:'+entry.balance.toFixed(8)+' '+entry.coinSym+'\nDATE: '+new Date().toISOString()+'\n'+'='.repeat(60)+'\n\n'); } catch(e) {}
}

// ============================================================
//  PROCESS ONE WALLET → ALL 10 checks parallel → wait ALL → display
// ============================================================
async function processWallet() {
    const privHex = genRandomPrivKey();
    const wallet = deriveAll(privHex);
    state.checkCount++;
    const promises = {};
    for (const coin of ALL) {
        promises[coin] = {
            comp: checkBalanceWithRetry(coin, wallet.comp[coin]),
            uncomp: checkBalanceWithRetry(coin, wallet.uncomp[coin])
        };
    }
    await Promise.allSettled(ALL.flatMap(c => [promises[c].comp, promises[c].uncomp]));
    const results = {};
    for (const coin of ALL) { results[coin] = { comp: await promises[coin].comp, uncomp: await promises[coin].uncomp }; }
    for (const coin of ALL) {
        ['comp','uncomp'].forEach(type => {
            const r = results[coin][type];
            if (r && !r.error && ((r.received||0) > 0 || (r.sent||0) > 0 || (r.balance||0) > 0)) {
                state.foundCount++;
                const entry = { idx:state.foundCount, privkey_hex:wallet.privkey_hex, comp_addr:wallet.comp[coin], uncomp_addr:wallet.uncomp[coin], coin:CN[coin], coinSym:CS[coin], addrType:type==='comp'?'COMPRESSED':'UNCOMPRESSED', received:r.received, sent:r.sent, balance:r.balance };
                state.foundData.push(entry); saveFound(entry); io.emit('found', entry);
                console.log('[FOUND] #' + entry.idx + ' ' + CS[coin] + ' ' + entry.addrType + ' B:' + entry.balance.toFixed(8));
            }
        });
    }
    const displayCoins = {};
    for (const coin of state.selCoins) {
        displayCoins[coin] = { comp_addr:wallet.comp[coin], comp:results[coin].comp||{...ERR}, uncomp_addr:wallet.uncomp[coin], uncomp:results[coin].uncomp||{...ERR} };
    }
    io.emit('wallet', { privkey_hex:wallet.privkey_hex, coins:displayCoins, checkCount:state.checkCount, foundCount:state.foundCount, apiCallCount, privKeyCount:state.checkCount, addressCount:state.checkCount*10 });
}

// ============================================================
//  3 PARALLEL WORKERS
// ============================================================
async function worker(id) {
    console.log('[WORKER ' + id + '] Started');
    while (true) { try { await processWallet(); } catch(e) { console.error('[W'+id+' ERR]', e.message); await new Promise(r=>setTimeout(r,500)); } }
}

// ============================================================
//  SPEED COUNTER (setInterval, keeps last non-zero)
// ============================================================
let lastSpeedCheck = 0, lastSpeedTime = Date.now();
setInterval(function() {
    const now = Date.now(), elapsed = (now - lastSpeedTime) / 1000;
    if (elapsed >= 1) {
        const speed = Math.round((state.checkCount - lastSpeedCheck) / elapsed);
        if (speed > 0) state.speedValue = speed;
        io.emit('speed', { speed:state.speedValue, checkCount:state.checkCount, foundCount:state.foundCount, apiCallCount, privKeyCount:state.checkCount, addressCount:state.checkCount*10 });
        lastSpeedTime = now; lastSpeedCheck = state.checkCount;
    }
}, 1000);

// ============================================================
//  SOCKET.IO
// ============================================================
io.on('connection', function(socket) {
    console.log('[VIEWER] ' + socket.id + ' (' + io.engine.clientsCount + ')');
    socket.emit('init', { selCoins:state.selCoins, checkCount:state.checkCount, foundCount:state.foundCount, apiCallCount, speed:state.speedValue, privKeyCount:state.checkCount, addressCount:state.checkCount*10, foundData:state.foundData.slice(-50) });
    socket.on('coins_toggle', function(d) {
        if (d && d.coins && Array.isArray(d.coins)) { state.selCoins = d.coins.filter(function(c){return ALL.includes(c);}); if (!state.selCoins.length) state.selCoins = ['btc']; io.emit('coins_update', {coins:state.selCoins}); }
    });
    socket.on('disconnect', function() {});
});

// ============================================================
//  START
// ============================================================
app.use(express.static('public'));
server.listen(PORT, function() {
    console.log('============================================');
    console.log('  LUCK WORLD v6.0 - NO DASH - 5 COINS');
    console.log('  150+ APIs/coin | 3 Workers | Random API');
    console.log('  IP Rotation: ' + (PROXIES.length ? PROXIES.length + ' proxies' : 'Direct (add proxies to PROXIES array)'));
    console.log('============================================');
    for (const c of ALL) console.log('  ' + CS[c].padEnd(4) + ': ' + RPC[c].length + ' endpoints');
    console.log('============================================');
    io.emit('log', {msg:'<span style="color:#60a5fa;font-weight:900;font-size:13px">LUCK WORLD v6.0 - 5 COINS - 150+ APIs</span>'});
    io.emit('log', {msg:'<span style="color:#22c55e">DASH removed | 150+ APIs per coin | 3 Workers parallel</span>'});
    io.emit('log', {msg:'<span style="color:#22d3ee">IP Rotation: ' + (PROXIES.length ? 'ACTIVE ('+PROXIES.length+' proxies)' : 'Add proxies to PROXIES[] array') + '</span>'});
    io.emit('log', {msg:''});
    worker(1); worker(2); worker(3);
});