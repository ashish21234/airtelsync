import assert from 'assert';
import fs from 'fs';
import path from 'path';
import {
  validateJwtSecretConfig,
  getJwtSecret,
  verifyCustomerOwnership,
  isOperationsRole,
  OPERATIONS_ROLES,
  signToken,
  verifyToken,
  AuthenticatedRequest,
} from '../middleware/auth';
import {
  runImagePdfPreprocessing,
  runModularOcrPipeline,
} from '../services/documentIntelligence';
import {
  runComprehensiveKycValidation,
} from '../services/kycEngine';

async function runSecurityAndOcrTests() {
  console.log('================================================================');
  console.log('UDYAM ONE — SECURITY, AUTH, DATA ISOLATION & OCR ACCEPTANCE SUITE');
  console.log('================================================================\n');

  let passed = 0;
  let failed = 0;

  async function test(id: string, name: string, fn: () => Promise<string> | string) {
    try {
      const detail = await fn();
      passed++;
      console.log(`✅ [PASS] ${id}: ${name}\n   -> ${detail}`);
    } catch (err: any) {
      failed++;
      console.error(`❌ [FAIL] ${id}: ${name}\n   -> ${err.message}`);
    }
  }

  // --------------------------------------------------------------------------
  // 1. JWT Secret Configuration & Hardening (P0 — Critical)
  // --------------------------------------------------------------------------
  await test('SEC-01', 'JWT Secret: Production startup fails if JWT_SECRET is missing', () => {
    const origEnv = process.env.NODE_ENV;
    const origSecret = process.env.JWT_SECRET;
    try {
      process.env.NODE_ENV = 'production';
      delete process.env.JWT_SECRET;
      assert.throws(
        () => validateJwtSecretConfig(),
        /FATAL CONFIGURATION ERROR: JWT_SECRET environment variable is missing/
      );
      return 'Fails application startup with fatal error when JWT_SECRET is missing in production.';
    } finally {
      process.env.NODE_ENV = origEnv;
      if (origSecret) process.env.JWT_SECRET = origSecret;
    }
  });

  await test('SEC-02', 'JWT Secret: Production startup fails if placeholder/default secret is used', () => {
    const origEnv = process.env.NODE_ENV;
    const origSecret = process.env.JWT_SECRET;
    try {
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = 'udyam_one_enterprise_secret_key_change_in_prod_2026';
      assert.throws(
        () => validateJwtSecretConfig(),
        /FATAL CONFIGURATION ERROR: Default or placeholder JWT_SECRET is strictly prohibited/
      );
      return 'Fails application startup with fatal error when fallback/default secret is used in production.';
    } finally {
      process.env.NODE_ENV = origEnv;
      if (origSecret) process.env.JWT_SECRET = origSecret;
    }
  });

  await test('SEC-03', 'JWT Secret: Production startup fails if secret is insufficiently strong (< 32 chars)', () => {
    const origEnv = process.env.NODE_ENV;
    const origSecret = process.env.JWT_SECRET;
    try {
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = 'short_secret_key_12345';
      assert.throws(
        () => validateJwtSecretConfig(),
        /FATAL CONFIGURATION ERROR: JWT_SECRET is insufficiently strong/
      );
      return 'Fails application startup with fatal error when secret length < 32 characters.';
    } finally {
      process.env.NODE_ENV = origEnv;
      if (origSecret) process.env.JWT_SECRET = origSecret;
    }
  });

  await test('SEC-04', 'JWT Secret: Valid strong production secret accepted & tokens signed/verified', () => {
    const origEnv = process.env.NODE_ENV;
    const origSecret = process.env.JWT_SECRET;
    try {
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = 'a_very_strong_production_secret_key_with_sufficient_entropy_2026!';
      const validated = validateJwtSecretConfig();
      assert.strictEqual(validated, process.env.JWT_SECRET);

      const token = signToken({
        userId: 'USR-PROD-01',
        email: 'prod@udyamone.in',
        name: 'Prod Admin',
        role: 'Admin',
      });
      const decoded = verifyToken(token);
      assert.strictEqual(decoded.email, 'prod@udyamone.in');
      return `Accepted valid 65-character production secret; signed & verified JWT successfully.`;
    } finally {
      process.env.NODE_ENV = origEnv;
      if (origSecret) process.env.JWT_SECRET = origSecret;
    }
  });

  // --------------------------------------------------------------------------
  // 2. Customer Data Isolation & Server-Side Ownership Enforcement (P0 — Critical)
  // --------------------------------------------------------------------------
  await test('SEC-05', 'Data Isolation: verifyCustomerOwnership() rejects unauthenticated requests', () => {
    const mockReq = { headers: {} } as AuthenticatedRequest;
    const result = verifyCustomerOwnership(mockReq, 'BIZ-SCEN-01');
    assert.strictEqual(result.allowed, false);
    assert(result.reason?.includes('AUTHENTICATION REQUIRED'));
    return `Unauthenticated request correctly rejected: allowed=false, reason='${result.reason}'`;
  });

  await test('SEC-06', 'Data Isolation: Client-supplied header (x-customer-business-id) is NOT accepted as authentication', () => {
    const mockReq = {
      headers: {
        'x-customer-business-id': 'BIZ-SCEN-01',
      },
    } as unknown as AuthenticatedRequest;

    const result = verifyCustomerOwnership(mockReq, 'BIZ-SCEN-01');
    assert.strictEqual(result.allowed, false);
    assert(result.reason?.includes('AUTHENTICATION REQUIRED'));
    return `Spoofed client header without JWT rejected with allowed=false. Client headers never substitute for authentication.`;
  });

  await test('SEC-07', 'Data Isolation: Customer JWT bound to business A cannot access business B', () => {
    const customerReq = {
      user: {
        userId: 'USR-CUST-01',
        email: 'cust1@example.com',
        name: 'Customer 1',
        role: 'Customer',
        businessId: 'BIZ-SCEN-01',
      },
      headers: {
        'x-customer-business-id': 'BIZ-SCEN-02', // Attempted header override
      },
    } as unknown as AuthenticatedRequest;

    // Access own business -> Allowed
    const ownAccess = verifyCustomerOwnership(customerReq, 'BIZ-SCEN-01');
    assert.strictEqual(ownAccess.allowed, true);

    // Cross-customer access to another business -> Denied
    const crossAccess = verifyCustomerOwnership(customerReq, 'BIZ-SCEN-02');
    assert.strictEqual(crossAccess.allowed, false);
    assert(crossAccess.reason?.includes('DATA ISOLATION VIOLATION'));
    return `Customer bound to 'BIZ-SCEN-01' allowed own access and strictly blocked from 'BIZ-SCEN-02' (ignoring spoofed header).`;
  });

  await test('SEC-08', 'Data Isolation: Customer without bound businessId is denied access to customer data', () => {
    const unboundCustomerReq = {
      user: {
        userId: 'USR-CUST-UNBOUND',
        email: 'unbound@example.com',
        name: 'Unbound Customer',
        role: 'Customer',
        businessId: undefined, // Missing binding
      },
      headers: {},
    } as unknown as AuthenticatedRequest;

    const res = verifyCustomerOwnership(unboundCustomerReq, 'BIZ-SCEN-01');
    assert.strictEqual(res.allowed, false);
    assert(res.reason?.includes('Customer account is not bound'));
    return `Unbound customer account denied with allowed=false.`;
  });

  await test('SEC-09', 'Data Isolation & RBAC: Operations roles pass explicit RBAC permissions', () => {
    assert.deepStrictEqual(
      OPERATIONS_ROLES,
      ['Admin', 'Sales Executive', 'Channel Partner', 'KYC Reviewer']
    );

    for (const opRole of OPERATIONS_ROLES) {
      assert.strictEqual(isOperationsRole(opRole), true);
      const opReq = {
        user: {
          userId: `USR-${opRole}`,
          email: `${opRole.toLowerCase().replace(/\s+/g, '')}@udyamone.in`,
          name: `${opRole} Officer`,
          role: opRole,
        },
        headers: {},
      } as AuthenticatedRequest;

      const access = verifyCustomerOwnership(opReq, 'BIZ-SCEN-01');
      assert.strictEqual(access.allowed, true, `Role '${opRole}' should have operational RBAC access`);
    }

    // Customer is NOT an operations role
    assert.strictEqual(isOperationsRole('Customer'), false);
    return `All 4 operational roles (${OPERATIONS_ROLES.join(', ')}) verified via explicit RBAC check.`;
  });

  // --------------------------------------------------------------------------
  // 3. OCR Reliability, Arbitrary File Uploads & Authenticity Assurance (P1)
  // --------------------------------------------------------------------------
  await test('OCR-01', 'OCR Preprocessing: Arbitrary PNG file header and IHDR magic bytes validated', () => {
    // Generate valid minimal PNG buffer: 8-byte PNG signature + IHDR chunk (13 bytes data)
    const pngBuf = Buffer.alloc(33);
    // PNG Magic: 0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(pngBuf, 0);
    // Chunk length: 13
    pngBuf.writeUInt32BE(13, 8);
    // Chunk type: IHDR
    pngBuf.write('IHDR', 12);
    // Width = 1600, Height = 1200
    pngBuf.writeUInt32BE(1600, 16);
    pngBuf.writeUInt32BE(1200, 20);

    const tmpPngPath = path.resolve(__dirname, 'temp_arbitrary_test.png');
    fs.writeFileSync(tmpPngPath, pngBuf);

    try {
      const diag = runImagePdfPreprocessing(tmpPngPath, 'customer_upload.png', 'image/png');
      assert.strictEqual(diag.detectedFormat, 'PNG');
      assert.strictEqual(diag.fileValid, true);
      assert.strictEqual(diag.widthPx, 1600);
      assert.strictEqual(diag.heightPx, 1200);
      assert(diag.preprocessingStepsApplied.includes('PNG_IHDR_DIMENSION_PARSED'));
      return `Detected PNG, parsed dimensions ${diag.widthPx}x${diag.heightPx} px, fileValid=true.`;
    } finally {
      if (fs.existsSync(tmpPngPath)) fs.unlinkSync(tmpPngPath);
    }
  });

  await test('OCR-02', 'OCR Preprocessing: Arbitrary JPEG file magic bytes validated', () => {
    // Generate valid minimal JPEG buffer: 0xFF 0xD8 0xFF (SOI) + SOF0 frame
    const jpgBuf = Buffer.alloc(64);
    jpgBuf[0] = 0xff;
    jpgBuf[1] = 0xd8;
    jpgBuf[2] = 0xff;
    jpgBuf[3] = 0xe0; // APP0 marker
    // Write SOF0 at offset 10
    jpgBuf[10] = 0xff;
    jpgBuf[11] = 0xc0;
    jpgBuf.writeUInt16BE(1080, 15); // Height
    jpgBuf.writeUInt16BE(1920, 17); // Width

    const tmpJpgPath = path.resolve(__dirname, 'temp_arbitrary_test.jpg');
    fs.writeFileSync(tmpJpgPath, jpgBuf);

    try {
      const diag = runImagePdfPreprocessing(tmpJpgPath, 'customer_bill.jpg', 'image/jpeg');
      assert.strictEqual(diag.detectedFormat, 'JPEG');
      assert.strictEqual(diag.fileValid, true);
      assert.strictEqual(diag.widthPx, 1920);
      assert.strictEqual(diag.heightPx, 1080);
      assert(diag.preprocessingStepsApplied.includes('JPEG_FRAME_HEADER_PARSED'));
      return `Detected JPEG, parsed dimensions ${diag.widthPx}x${diag.heightPx} px, fileValid=true.`;
    } finally {
      if (fs.existsSync(tmpJpgPath)) fs.unlinkSync(tmpJpgPath);
    }
  });

  await test('OCR-03', 'OCR Preprocessing: Arbitrary PDF document magic bytes validated', () => {
    // Generate minimal PDF header (%PDF-1.7)
    const pdfBuf = Buffer.from('%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF');
    const tmpPdfPath = path.resolve(__dirname, 'temp_arbitrary_test.pdf');
    fs.writeFileSync(tmpPdfPath, pdfBuf);

    try {
      const diag = runImagePdfPreprocessing(tmpPdfPath, 'customer_contract.pdf', 'application/pdf');
      assert.strictEqual(diag.detectedFormat, 'PDF');
      assert.strictEqual(diag.fileValid, true);
      assert(diag.preprocessingStepsApplied.includes('PDF_MAGIC_BYTES_VERIFIED'));
      return `Detected PDF format (%PDF-), standard rendered A4 bounds, fileValid=true.`;
    } finally {
      if (fs.existsSync(tmpPdfPath)) fs.unlinkSync(tmpPdfPath);
    }
  });

  await test('OCR-04', 'OCR Pipeline: Transparent provider attribution differentiates Specimen vs Fallback', async () => {
    // 1. Specimen file K01
    const specResult = await runModularOcrPipeline({
      documentType: 'GST_CERTIFICATE',
      fileName: 'K01_gst_certificate.png',
      mimeType: 'image/png',
      fileSizeBytes: 150000,
    });
    assert.strictEqual(specResult.providerUsed, 'Catalog-Specimen-GroundTruth-Adapter (K01-K12)');
    assert.strictEqual(specResult.isGeneralPurposeOcr, false);

    // 2. Arbitrary non-specimen file
    const customResult = await runModularOcrPipeline({
      documentType: 'GST_CERTIFICATE',
      fileName: 'random_customer_document.png',
      mimeType: 'image/png',
      fileSizeBytes: 120000,
    });
    assert.strictEqual(customResult.providerUsed, 'RuleBased-Heuristic-Fallback-Adapter (Non-Production-OCR)');
    assert.strictEqual(customResult.isGeneralPurposeOcr, false);
    assert(customResult.qualityFlags.some((f) => f.includes('HEURISTIC_PARSER_FALLBACK')));
    assert(customResult.qualityFlags.some((f) => f.includes('MANUAL_ESCALATION_RECOMMENDED')));

    return `Specimen attributed to Catalog adapter; arbitrary upload explicitly labeled as heuristic fallback with manual escalation recommended.`;
  });

  await test('OCR-05', 'OCR Reliability: Missing fields on arbitrary upload drop confidence & trigger manual escalation', async () => {
    const blankUpload = await runModularOcrPipeline({
      documentType: 'GST_CERTIFICATE',
      fileName: 'arbitrary_unrelated_photo.jpg',
      mimeType: 'image/jpeg',
      fileSizeBytes: 95000,
    });

    assert(blankUpload.overallConfidence < 0.60, `Expected confidence < 0.60, got ${blankUpload.overallConfidence}`);
    assert(blankUpload.qualityFlags.some((f) => f.includes('MISSING_FIELD')));
    assert.strictEqual(blankUpload.authenticityAudit.escalationRequired, true);
    assert.strictEqual(blankUpload.authenticityAudit.authenticityStatus, 'REQUIRES_MANUAL_REVIEW');

    return `Arbitrary upload with missing fields received confidence=${blankUpload.overallConfidence} and escalated to MANUAL_REVIEW.`;
  });

  await test('OCR-06', 'Authenticity Assurance: High visual OCR confidence score alone NEVER proves document authenticity', async () => {
    // Test that high visual clarity (confidence = 0.99) alone does not auto-verify an unverified/tampered document
    const validation = await runComprehensiveKycValidation({
      businessName: 'Unverified Enterprise',
      gstinInput: '99AAAAA0000A1Z5', // Invalid fake GSTIN
      ocrConfidenceOverride: 0.99, // Artificially high visual clarity score
    });

    // Despite 0.99 OCR clarity, authenticity audit must state confidence alone is not sufficient
    assert.strictEqual(validation.authenticityAudit.confidenceAloneProvesAuthenticity, false);
    assert.strictEqual(validation.authenticityAudit.isAuthentic, false);
    assert.strictEqual(validation.authenticityAudit.escalationRequired, true);
    assert.notStrictEqual(validation.determinedStatus, 'VERIFIED');

    return `Verified architectural guarantee: 99% visual OCR confidence alone did NOT prove authenticity; invalid registry record resulted in status=${validation.determinedStatus}.`;
  });

  console.log('\n================================================================');
  console.log(`ACCEPTANCE SUMMARY: ${passed} PASSED | ${failed} FAILED (Total: ${passed + failed})`);
  console.log('================================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runSecurityAndOcrTests();

