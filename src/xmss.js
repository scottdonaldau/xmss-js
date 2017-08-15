#!/usr/bin/env node

'use strict';

var sha256 = require('js-sha256');

var x = sha256('cows');
// console.log(x + '  <-- SHA256');

const utf8 = require('utf8');
const crypto = require('crypto');
const ba = require('binascii');
const format = require('biguint-format');
const {wordlist} = require('./wordlist.js');

const ord = string => {
  var str = string + ''
  var code = str.charCodeAt(0)
  return code
}

const seed_to_mnemonic = SEED => {
  if (SEED.length != 48) {
    console.log('ERROR: SEED is not 48 bytes in length: ' + SEED.length);
    return false
  }
  // var SEED = utf8.encode(SEED);
  var words = [];
  for (var i = 0; i < SEED.length; i=i+3) {
    var three = ("00000000"+ord(SEED[i]).toString(2)).slice(-8)+("00000000"+ord(SEED[i+1]).toString(2)).slice(-8)+("00000000"+ord(SEED[i+2]).toString(2)).slice(-8);
    words.push(wordlist[(parseInt(three.slice(0,12),2))]);
    words.push(wordlist[(parseInt(three.slice(12),2))]);
  }
  return words.join(" ");
};

const mnemonic_to_seed = mnemonic => {
    var words = mnemonic.split(' ');
    if (words.length != 32) {
         console.log('ERROR: mnemonic is not 32 words in length: ' + words.length);
         return false
	}
    var buf = new Buffer(48);
    var y=0;
    for (var x = 0; x < 32; x=x+2) {
      // console.log(words[x] + ' (' + wordlist.indexOf(words[x]) + ') and ' + words[x+1] + ' (' + wordlist.indexOf(words[x+1]) + ')');
    	var b = ("000000000000"+(wordlist.indexOf(words[x])).toString(2)).slice(-12);
    	var c = ("000000000000"+(wordlist.indexOf(words[x+1])).toString(2)).slice(-12);
    var three = b + c;
    // console.log(three);
    	    	var first = three.slice(0,8);
    	    	var second = three.slice(8,16);
            var third = three.slice(16);
            // console.log('first: ' + String.fromCharCode(parseInt(first,2)) + ' second: ' + String.fromCharCode(parseInt(second,2)) + 'third: ' + String.fromCharCode(parseInt(third,2)));
            buf[y] = ord(String.fromCharCode(parseInt(first,2)));
            buf[y+1] = ord(String.fromCharCode(parseInt(second,2)));
            buf[y+2] = ord(String.fromCharCode(parseInt(third,2)));
    	    	y+=3;
    }
return buf
};



console.log('\n\nxmss-js\n=======\n\nTesting functions against known values');

var pete = mnemonic_to_seed('lipic berime whiney rammed madge feeds emoted rewax deynt casula sebkha pareu pebbly haps maes finest mund lobby boryl camper mochel sobeit volar indoor uplook mobed gnarly capon reem hilt etwees aube');
if (pete.toString('hex') === '81c168f71b1a85c4dd475b843c5267c31a0fa2e62c8624ef9178231cd2418d4cdbf276deed08d25bf24bb4866b4a10fa') {
  console.log('c.f. python: mnemonic_to_seed PASSING');
} else {
  console.log('c.f. python: mnemonic_to_seed *** FAILING ***');
}
pete = seed_to_mnemonic(ba.unhexlify('81c168f71b1a85c4dd475b843c5267c31a0fa2e62c8624ef9178231cd2418d4cdbf276deed08d25bf24bb4866b4a10fa'));
if (pete.toString('hex') === 'lipic berime whiney rammed madge feeds emoted rewax deynt casula sebkha pareu pebbly haps maes finest mund lobby boryl camper mochel sobeit volar indoor uplook mobed gnarly capon reem hilt etwees aube') {
  console.log('c.f. python: seed_to_mnemonic PASSING\n\n');
} else {
  console.log('c.f. python: seed_to_mnemonic *** FAILING ***\n\n');
}
//  console.log(ba.unhexlify('81c168f71b1a85c4dd475b843c5267c31a0fa2e62c8624ef9178231cd2418d4cdbf276deed08d25bf24bb4866b4a10fa'));
var seed = crypto.randomBytes(48);
console.log('>> RANDOM SEED:');
console.log(seed.toString('hex') + '\n');
var mnemonic = seed_to_mnemonic(ba.unhexlify(seed.toString('hex')));
console.log('>> SEED-TO-MNEMONIC:');
console.log(mnemonic);
var moo = mnemonic_to_seed(mnemonic);
console.log('\n>> MNEMONIC-TO-SEED:');
console.log(moo.toString('hex') + '\n');
if (seed.toString('hex') === moo.toString('hex')) {
  console.log('round trip PASSING\n\n');
} else {
  console.log('round trip *** FAILING ***\n\n');
}

/* 
>>> tree = merkle.XMSS(signatures=512, SEED=seed)
>>> msg = 'this is something to sign'
>>> signature = tree.SIGN(msg)
[unsynced|-1] xmss signing with OTS n =  0
>>> tree.VERIFY(msg, signature)
True
>>> msg = 'this isnt the same message'
>>> tree.VERIFY(msg, signature)
False
>>> tree.address
'Qce75a63ea23a1b84915b00fb75495976452693391c34c60633a83826237fa91a7423'
>>> tree.hexSEED
'09e1c330bc7d9af6b3100e73d44d6641449be6e99627ee4a84e1d3978c9244e11d1157cde68f31957feac7c421d45208'
>>> tree.mnemonic
'angels bopeep corody sicked oleums icier aurei tushy stop sughs dougl espec tuque ocelli ceric trityl lurdan bouk norm sish dysury bairdi babbie laith tuners waggie nikon zenick sicced drats stoper bun'
>>> tree.signatures
512
>>> tree.index
1
>>> 
*/