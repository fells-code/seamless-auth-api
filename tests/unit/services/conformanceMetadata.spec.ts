import { SettingsService } from '@simplewebauthn/server';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { applyConformanceMetadataOverrides } from '../../../src/services/conformanceMetadata';

// SettingsService is the thing under test here, and the shared setup stubs the
// library it comes from.
vi.unmock('@simplewebauthn/server');

const VARS = [
  'FIDO_CONFORMANCE_MDS_URLS',
  'FIDO_CONFORMANCE_MDS_ROOT_CERT_FILE',
  'FIDO_CONFORMANCE_METADATA_DIR',
];

let tmpDir: string;

beforeEach(() => {
  for (const name of VARS) delete process.env[name];
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'conformance-metadata-'));
});

afterEach(() => {
  for (const name of VARS) delete process.env[name];
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('applyConformanceMetadataOverrides', () => {
  it('returns nothing when no conformance metadata is configured', () => {
    expect(applyConformanceMetadataOverrides()).toEqual({});
  });

  it('collects MDS endpoints, ignoring blank entries', () => {
    process.env.FIDO_CONFORMANCE_MDS_URLS = 'https://mds3.example/one, https://mds3.example/two ,,';

    expect(applyConformanceMetadataOverrides().mdsServers).toEqual([
      'https://mds3.example/one',
      'https://mds3.example/two',
    ]);
  });

  it('installs the conformance MDS root certificate', () => {
    const certFile = path.join(tmpDir, 'root.pem');
    const pem = '-----BEGIN CERTIFICATE-----\nconformance\n-----END CERTIFICATE-----\n';
    fs.writeFileSync(certFile, pem);
    process.env.FIDO_CONFORMANCE_MDS_ROOT_CERT_FILE = certFile;

    const spy = vi
      .spyOn(SettingsService, 'setRootCertificates')
      .mockImplementation(() => undefined);

    applyConformanceMetadataOverrides();

    expect(spy).toHaveBeenCalledWith({ identifier: 'mds', certificates: [pem] });
    spy.mockRestore();
  });

  it('carries on when the root certificate cannot be read', () => {
    process.env.FIDO_CONFORMANCE_MDS_ROOT_CERT_FILE = path.join(tmpDir, 'missing.pem');

    expect(applyConformanceMetadataOverrides()).toEqual({});
  });

  it('loads statements both bare and wrapped in an MDS entry, skipping unreadable ones', () => {
    fs.writeFileSync(path.join(tmpDir, 'bare.json'), JSON.stringify({ aaguid: 'bare' }));
    fs.writeFileSync(
      path.join(tmpDir, 'wrapped.json'),
      JSON.stringify({ metadataStatement: { aaguid: 'wrapped' } }),
    );
    fs.writeFileSync(path.join(tmpDir, 'broken.json'), 'not json');
    fs.writeFileSync(path.join(tmpDir, 'ignored.txt'), 'not a statement');
    process.env.FIDO_CONFORMANCE_METADATA_DIR = tmpDir;

    const statements = applyConformanceMetadataOverrides().statements ?? [];

    expect(statements.map((statement: any) => statement.aaguid).sort()).toEqual([
      'bare',
      'wrapped',
    ]);
  });

  it('skips a statement file that parses to something that is not an object', () => {
    fs.writeFileSync(path.join(tmpDir, 'scalar.json'), '"just a string"');
    process.env.FIDO_CONFORMANCE_METADATA_DIR = tmpDir;

    expect(applyConformanceMetadataOverrides()).toEqual({});
  });

  it('carries on when the statement directory cannot be read', () => {
    process.env.FIDO_CONFORMANCE_METADATA_DIR = path.join(tmpDir, 'missing');

    expect(applyConformanceMetadataOverrides()).toEqual({});
  });
});
