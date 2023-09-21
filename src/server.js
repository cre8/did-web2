import express from 'express'
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'fs'
import { join, resolve } from 'path';
import {generateKeyPair, exportJWK, importJWK, SignJWT} from 'jose';
import { proofEndpoint, updateType, domain } from './const.mjs';
import { createHash } from 'crypto'

const app = express();

const didDocFolder = './tmp';
if(!existsSync(didDocFolder)) mkdirSync(didDocFolder);

if(!existsSync(join(didDocFolder, 'proofs.json'))) {
  writeFileSync(join(didDocFolder, 'proofs.json'), JSON.stringify({}));
}

if(!existsSync(join(didDocFolder, 'counter.json'))) {
  writeFileSync(join(didDocFolder, 'counter.json'), JSON.stringify({counter: 0}));
}

if(!existsSync(join(didDocFolder, '1.json'))) {
  createDidDoc(domain, domain, 1);
};

async function createDidDoc(id, domain, version) {
  const { publicKey, privateKey } = await generateKeyPair('ES256')
  const did = `did:web:${id}`;
  const jwk = await exportJWK(publicKey);
    const doc = {
        id,
        verificationMethod: [
          {
            id: `${did}#key-0`,
            type: "JsonWebKey2020",
            controller: id,
            publicKeyJwk: jwk,
          },                             
        ],
        authentication: [
          `${did}#key-0`,          
        ],
        assertionMethod: [
          `${did}#key-0`,          
        ],
        service: [
            {
                id: `${did}#update`,
                type: updateType,
                serviceEndpoint: `https://${domain}/${proofEndpoint}`
            }
        ]        
      }
  if(version > 1) {
    console.log(version);
    const oldKey = await importJWK(JSON.parse(readFileSync(join(didDocFolder, 'privateKey.json'), 'utf8')));
    const hash = createHash('sha256').update(JSON.stringify(doc)).digest('hex');
    const jwt = await new SignJWT({sub: hash, iss: `${did}?versionId=${version - 1}#key-0`}).setProtectedHeader({alg: 'ES256'}).sign(oldKey);
    const proofs = JSON.parse(readFileSync(join(didDocFolder, 'proofs.json'), 'utf8'));
    proofs[version - 1] = jwt;    
    console.log(proofs);
    writeFileSync(join(didDocFolder, 'proofs.json'), JSON.stringify(proofs, null, 4));
  }

  // store the new values
  writeFileSync(join(didDocFolder, `${version}.json`), JSON.stringify(doc));  
  writeFileSync(join(didDocFolder, `privateKey.json`), JSON.stringify(await exportJWK(privateKey)));
  writeFileSync(join(didDocFolder, 'counter.json'), JSON.stringify({counter: version}));
}


app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.get('/update', async (req, res) => {
  const counter = JSON.parse(readFileSync(join(didDocFolder, 'counter.json'), 'utf8')).counter;
  await createDidDoc(domain, domain, counter + 1);
  res.send('OK');
});

app.get('/.well-known/did.json', (req, res) => {
    // TODO we need to get the metadata from the request, but did.json is only allowing us to return the did.json file
    const versionId = req.query?.versionId;    
    try {
    const file = readFileSync(resolve(didDocFolder, `${versionId}.json`), 'utf8');  
    res.send(JSON.parse(file));
    } catch(e) {
      res.status(404).send('Not found');
    }
});

app.get('/.well-known/metadata.json', (req, res) => {
  // TODO we need to get the metadata from the request, but did.json is only allowing us to return the did.json file
  const versionId = parseInt(req.query?.versionId);
  const nextVersionId = existsSync(resolve(didDocFolder, `${versionId + 1}.json`));  
  
  const metadata = {        
    versionId: versionId,
    nextVersionId,
  };
  res.send(metadata);  
});

app.get(`/${proofEndpoint}`, (req, res) => {
   res.send(JSON.parse(readFileSync(join(didDocFolder, 'proofs.json'), 'utf8')));
});

app.listen(3000);