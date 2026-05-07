const BLOCK_SIZE_CHAR = 4;
const BLOCK_SIZE_BIT = 32; 

function textToBiner(text) {
    let biner = "";
    for (let i = 0; i < text.length; i++) {
        biner += (text.charCodeAt(i) & 0xFF).toString(2).padStart(8, '0');
    }
    return biner;
}

function binerToText(biner) {
    let text = "";
    for (let i = 0; i < biner.length; i += 8) {
        text += String.fromCharCode(parseInt(biner.substring(i, i + 8), 2));
    }
    return text;
}

function binerToHex(biner) {
    let hex = "";
   
    for (let i = 0; i < biner.length; i += 4) {
        let chunk = biner.substring(i, i + 4);
        hex += parseInt(chunk, 2).toString(16).toUpperCase();
    }
    return hex;
}

function hexToBiner(hex) {
    let biner = "";
    for (let i = 0; i < hex.length; i++) {
        biner += parseInt(hex[i], 16).toString(2).padStart(4, '0');
    }
    return biner;
}

function pad(text) {
    let padded = text;
    while (padded.length % BLOCK_SIZE_CHAR !== 0) padded += ' ';
    return padded;
}

function formatBin(binStr) {
    return binStr.match(/.{1,8}/g).join(' ');
}

const IV_BIN = textToBiner("INIT");

function transposisi(binBlock) {
    let left = binBlock.substring(0, 16);
    let right = binBlock.substring(16, 32);
    return right + left;
}
function inv_transposisi(binBlock) {
    return transposisi(binBlock); 
}

function substitusi(binBlock, shiftKey) {
    let res = "";
    for (let i = 0; i < 32; i += 8) {
        let val = parseInt(binBlock.substring(i, i + 8), 2);
        val = (val + shiftKey) % 256;
        res += val.toString(2).padStart(8, '0');
    }
    return res;
}
function inv_substitusi(binBlock, shiftKey) {
    let res = "";
    for (let i = 0; i < 32; i += 8) {
        let val = parseInt(binBlock.substring(i, i + 8), 2);
        val = (val - shiftKey) % 256;
        if (val < 0) val += 256; 
        res += val.toString(2).padStart(8, '0');
    }
    return res;
}

function permutasi(binBlock) {
    return binBlock.split('').reverse().join('');
}
function inv_permutasi(binBlock) {
    return permutasi(binBlock); 
}

function operasi_xor(binBlock, binKey) {
    let res = "";
    for (let i = 0; i < binBlock.length; i++) {
        res += (binBlock[i] === binKey[i % binKey.length]) ? '0' : '1';
    }
    return res;
}

function proses_ecb(binText, isEncrypt, shiftKey) {
    let hasilAkhir = "";
    let logText = "";

    for (let i = 0; i < binText.length; i += BLOCK_SIZE_BIT) {
        let block = binText.substring(i, i + BLOCK_SIZE_BIT);
        logText += `\n--- Memproses Blok:\n[${formatBin(block)}] ---\n`;
        
        if (isEncrypt) {
            let step1 = transposisi(block);
            let step2 = substitusi(step1, shiftKey);
            let step3 = permutasi(step2);
            logText += `1. Transposisi : ${formatBin(step1)}\n2. Substitusi  : ${formatBin(step2)}\n3. Permutasi   : ${formatBin(step3)}\n`;
            hasilAkhir += step3;
        } else {
            let step1 = inv_permutasi(block);
            let step2 = inv_substitusi(step1, shiftKey);
            let step3 = inv_transposisi(step2);
            logText += `1. Inv_Permutasi  : ${formatBin(step1)}\n2. Inv_Substitusi : ${formatBin(step2)}\n3. Inv_Transposisi: ${formatBin(step3)}\n`;
            hasilAkhir += step3;
        }
    }
    return { hasil: hasilAkhir, log: logText };
}

function proses_cbc(binText, isEncrypt, shiftKey) {
    let hasilAkhir = "";
    let logText = "";
    let prevBlock = IV_BIN;

    for (let i = 0; i < binText.length; i += BLOCK_SIZE_BIT) {
        let block = binText.substring(i, i + BLOCK_SIZE_BIT);
        logText += `\n--- Memproses Blok:\n[${formatBin(block)}] ---\n`;

        if (isEncrypt) {
            let chained = operasi_xor(block, prevBlock);
            logText += `-> Chaining (XOR dgn prev block): \n   ${formatBin(chained)}\n`;
            
            let step1 = transposisi(chained);
            let step2 = substitusi(step1, shiftKey);
            
            logText += `1. Transposisi   : ${formatBin(step1)}\n2. Substitusi    : ${formatBin(step2)}\n`;
            hasilAkhir += step2;
            prevBlock = step2; 
        } else {
            let step1 = inv_substitusi(block, shiftKey);
            let step2 = inv_transposisi(step1);
            
            logText += `1. Inv_Substitusi : ${formatBin(step1)}\n2. Inv_Transposisi: ${formatBin(step2)}\n`;
            
            let unchained = operasi_xor(step2, prevBlock);
            logText += `-> Unchaining (XOR dgn prev block): \n   ${formatBin(unchained)}\n`;
            
            hasilAkhir += unchained;
            prevBlock = block; 
        }
    }
    return { hasil: hasilAkhir, log: logText };
}

function jalankanProses() {
    let isEncrypt = document.querySelector('input[name="aksi"]:checked').value === "encrypt";
    let mode = document.querySelector('input[name="mode"]:checked').value;
    let shiftKey = parseInt(document.getElementById("shiftKey").value);
    let xorKey = document.getElementById("xorKey").value;
    let inputText = document.getElementById("inputText").value;

    let logOutput = document.getElementById("logText");
    let resultOutput = document.getElementById("outputText");

    if (!inputText) return alert("Error: Teks input tidak boleh kosong!");
    if (isNaN(shiftKey)) return alert("Error: Kunci Substitusi harus berupa angka!");
    if (mode === "CBC" && !xorKey) return alert("Error: Kunci XOR tidak boleh kosong untuk mode CBC!");

    let binerProses = "";
    let binXorKey = textToBiner(xorKey);

    if (isEncrypt) {
        let textPadded = pad(inputText);
        binerProses = textToBiner(textPadded);
    } else {
        let cleanHex = inputText.replace(/\s+/g, '').toUpperCase();
        if (!/^[0-9A-F]+$/.test(cleanHex)) {
            return alert("Error: Input untuk decrypt HARUS berupa karakter Hexadecimal (0-9, A-F)!");
        }
        
        binerProses = hexToBiner(cleanHex);
        
        if (binerProses.length % 32 !== 0) {
            return alert("Error: Teks Hexadecimal tidak lengkap (hilang saat copy-paste)!");
        }
    }

    logOutput.value = "=== MEMULAI PROSES DI LEVEL BINER ===\n";
    let resultObj;

    if (mode === "ECB") {
        resultObj = proses_ecb(binerProses, isEncrypt, shiftKey);
    } else {
        resultObj = proses_cbc(binerProses, isEncrypt, shiftKey, binXorKey);
    }

    logOutput.value += resultObj.log + "\n=== SELESAI ===";

    if (isEncrypt) {
        let hexString = binerToHex(resultObj.hasil);
        let formattedHex = hexString.match(/.{1,8}/g).join(' ');
        resultOutput.value = formattedHex;
    } else {
        resultOutput.value = binerToText(resultObj.hasil).trim();
    }
}