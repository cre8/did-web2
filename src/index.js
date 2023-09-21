import { decodeJwt, importJWK, jwtVerify} from 'jose';
import { updateType, domain } from './const.mjs';
import { createHash } from 'crypto';
import { getDefaultResultOrder } from 'dns';

(async () => {
    // this is the verson for which the credential is issued and therefore our trust anchor
    let currentVersion = '2';
    // TODO compare it with the hash that was in the credential.    
    // pass the hash to the function to make sure it fits the document
    let didDoc = await resolve(`did:web:${domain}?versionId=${currentVersion}`);
    currentVersion++;
    while(true) {
        console.log("checking version", currentVersion);
        //get the next document in the chain
        const nextDidDoc = await resolve(`did:web:${domain}?versionId=${currentVersion}`);        
        // compare it against the proof
        await checkProof(nextDidDoc, didDoc, currentVersion);
        if(!await isLast(domain, currentVersion)) break;
        currentVersion++;
        didDoc = nextDidDoc;        
    }
    console.log('All proofs are valid');
})();

async function isLast(domain, currentVersion) {
    const res = await fetch(getUrl(`did:web:${domain}?versionId=${currentVersion + 1}`).replace('did.json', 'metadata.json')).then(res => res.json());    
    return res.nextVersionId;
}

/**
 * Creates the url based on the did
 * @param {*} did 
 * @returns 
 */
function getUrl(did) {
    did = did.slice(8);
    const helpers = did.split('?');
    let path = helpers[0];
    const params = helpers.length > 0 ? helpers[1] : '';    
    path += did.includes(':') ? '' : '/.well-known';
    return `https://${path}/did.json?${params}`; 
}

/**
 * Resolves the did document from the webserver
 * @param {*} did 
 * @returns did document as json object ö
 */
async function resolve(did) {
    const urlValue = getUrl(did); 
    const result = await fetch(urlValue).then(res => res.json());
    return result;
}

/**
 * Calculates the hash of the document
 * @param {*} doc 
 * @returns 
 */
function getHash(doc) {
    return createHash('sha256').update(JSON.stringify(doc)).digest('hex');    
}

/**
 * Checks if the hash of the document matches with the passed hash
 * @param {*} doc 
 * @param {*} correctHash 
 */
function checkIntegrity(doc, correctHash) {
    const hash = getHash(doc);
    if(correctHash && hash !== correctHash) throw new Error('Hashes do not match');    
}

/**
 * Validates if the proof that got signed with a key of the last document is valid and if the sub of the proof matches with the hash of the new document
 * @param {*} newDoc 
 * @param {*} lastDoc 
 * @param {*} version 
 */
async function checkProof(newDoc, lastDoc, version) {
    if(!newDoc.service) throw new Error('No service endpoint found');
    
    const service = newDoc.service.find((service) => service.type === updateType);        
    
    if(!service) throw new Error('No update service endpoint found');

    // get the proofs
    const proofs = await fetch(service.serviceEndpoint).then(res => res.json(), () => {
        throw new Error('Endpoint not found');
    });
    // select the correct proof based on the did doc version
    const proof = proofs[version - 1];
    const jwt = await decodeJwt(proof);        
    const publicKey = lastDoc.verificationMethod.find(key => key.id.split('#')[1] === jwt.iss.split('#')[1]).publicKeyJwk
    // validate the signature of the proof
    const valid = await jwtVerify(proof, await importJWK(publicKey));    
    if(!valid) throw new Error('Proof is not valid');
    // check if the signed hash matches the hash of the last document
    checkIntegrity(newDoc, valid.payload.sub);
}