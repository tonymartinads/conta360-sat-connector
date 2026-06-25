// ─── CONTA360 SAT CONNECTOR v8.0 ───
// Microservicio Node.js externo para comunicacion SAT WS-Security.
// Usa @nodecfdi/sat-ws-descarga-masiva en Node.js REAL (NO Deno).
//
// v8.0: Agrega endpoints /api/validate-files, /api/query, /api/verify, /api/download
//       Corrige DownloadType a constructor seguro new DownloadType("issued"/"received")
//       Agrega logs estructurados por etapa internos
//       Mantiene compatibilidad con /query, /verify existentes

const BUILD_ID = 'v8.0-20250625-001';

console.log('[sat-connector] === INICIANDO server.js ===');
console.log('[sat-connector] BUILD_ID:', BUILD_ID);
console.log('[sat-connector] Directorio:', __dirname);
console.log('[sat-connector] Archivo:', __filename);
console.log('[sat-connector] PORT env:', process.env.PORT);
console.log('[sat-connector] SAT_CONNECTOR_SECRET configurado:', !!process.env.SAT_CONNECTOR_SECRET);

const express = require('express');
const {
  Fiel,
  FielRequestBuilder,
  HttpsWebClient,
  Service,
  QueryParameters,
  DateTimePeriod,
  DownloadType,
} = require('@nodecfdi/sat-ws-descarga-masiva');

const AUTH_SECRET = process.env.SAT_CONNECTOR_SECRET || 'conta360-sat-connector-2026';
const PORT = parseInt(process.env.PORT || '3000', 10);

console.log('[sat-connector] AUTH_SECRET configurado:', AUTH_SECRET.length > 0);
console.log('[sat-connector] PORT final:', PORT);

const app = express();
app.use(express.json({ limit: '10mb' }));

// ─── LOGGING MIDDLEWARE: registra TODAS las peticiones ───
app.use((req, _res, next) => {
  console.log(`[sat-connector] ${new Date().toISOString()} ${req.method} ${req.path} - IP: ${req.ip || req.connection.remoteAddress}`);
  next();
});

// ─── MIDDLEWARE: Autenticacion simple con shared secret ───
function authMiddleware(req, res, next) {
  const token = req.headers['x-sat-connector-auth'] || '';
  if (token !== AUTH_SECRET) {
    console.log('[sat-connector] Auth rechazado. Header recibido:', token.slice(0, 10) + '...', 'Esperado:', AUTH_SECRET.slice(0, 10) + '...');
    return res.status(401).json({ success: false, error: 'Unauthorized', detail: 'Invalid x-sat-connector-auth header' });
  }
  next();
}

// ─── HELPERS ───
function fromBase64(b64) {
  return Buffer.from(b64, 'base64');
}

function sanitizeError(err) {
  if (err instanceof Error) return err.message.slice(0, 800);
  return String(err).slice(0, 800);
}

function sanitizeStack(err) {
  if (err instanceof Error && err.stack) {
    const lines = err.stack.split('\n').slice(0, 5);
    return lines.map(l => l.trim()).join(' | ');
  }
  return null;
}

function extractSatFaultDetails(err) {
  const msg = sanitizeError(err);
  const fcMatch = msg.match(/faultcode[:\s]*([^\s,]+)/i);
  const fsMatch = msg.match(/faultstring[:\s]*"?([^"]+)"?/i);
  return {
    faultCode: fcMatch?.[1] || null,
    faultString: fsMatch?.[1] || null,
  };
}

function safeStageLog(stage, data) {
  const sanitized = { ...data };
  delete sanitized.cerBase64;
  delete sanitized.keyBase64;
  delete sanitized.password;
  delete sanitized.cerBytes;
  delete sanitized.keyBytes;
  delete sanitized.certContent;
  delete sanitized.keyContent;
  delete sanitized.fiel;
  delete sanitized.requestBuilder;
  return { stage, ...sanitized, timestamp: new Date().toISOString() };
}

// ─── GET /version ───
app.get('/version', (_req, res) => {
  console.log('[sat-connector] GET /version recibido. BUILD_ID:', BUILD_ID);
  res.json({
    build_id: BUILD_ID,
    service: 'conta360-sat-connector',
    version: '8.0',
    runtime: 'node',
    node_version: process.version,
    library: '@nodecfdi/sat-ws-descarga-masiva@2.0.0',
    timestamp: new Date().toISOString(),
  });
});

// ─── GET /routes ───
app.get('/routes', (_req, res) => {
  const routes = [];
  app._router.stack.forEach((layer) => {
    if (layer.route) {
      const methods = Object.keys(layer.route.methods).map((m) => m.toUpperCase());
      routes.push({ methods, path: layer.route.path });
    }
  });
  res.json({
    build_id: BUILD_ID,
    service: 'conta360-sat-connector',
    routes,
    route_count: routes.length,
    timestamp: new Date().toISOString(),
  });
});

// ─── GET / ───
app.get('/', (_req, res) => {
  res.json({
    service: 'conta360-sat-connector',
    version: '8.0',
    build_id: BUILD_ID,
    runtime: 'node',
    node_version: process.version,
    library: '@nodecfdi/sat-ws-descarga-masiva@2.0.0',
    timestamp: new Date().toISOString(),
    routes: [
      { method: 'GET', path: '/', description: 'Info del servicio' },
      { method: 'GET', path: '/version', description: 'Build ID del despliegue' },
      { method: 'GET', path: '/routes', description: 'Rutas reales registradas en Express' },
      { method: 'GET', path: '/health', description: 'Healthcheck' },
      { method: 'POST', path: '/echo', description: 'Diagnostico - eco simple' },
      { method: 'POST', path: '/query', description: 'Consulta SAT (legado)' },
      { method: 'POST', path: '/verify', description: 'Verifica solicitud (legado)' },
      { method: 'POST', path: '/cert-info', description: 'Info del certificado' },
      { method: 'POST', path: '/api/validate-files', description: 'Validar FIEL (.cer + .key)' },
      { method: 'POST', path: '/api/query', description: 'Consulta SAT DescargaMasiva (oficial)' },
      { method: 'POST', path: '/api/verify', description: 'VerificaSolicitudDescarga (oficial)' },
      { method: 'POST', path: '/api/download', description: 'Descargar paquete SAT (oficial)' },
    ],
  });
});

// ─── HEALTH ───
app.get('/health', (_req, res) => {
  console.log('[sat-connector] Healthcheck recibido');
  res.json({
    status: 'ok',
    build_id: BUILD_ID,
    service: 'conta360-sat-connector',
    version: '8.0',
    runtime: 'node',
    library: '@nodecfdi/sat-ws-descarga-masiva@2.0.0',
    timestamp: new Date().toISOString(),
  });
});

// ─── POST /echo ───
app.post('/echo', (req, res) => {
  console.log('[sat-connector] POST /echo recibido. Body:', JSON.stringify(req.body).slice(0, 200));
  res.json({
    success: true,
    message: 'POST /echo funciona correctamente',
    build_id: BUILD_ID,
    received_body_keys: Object.keys(req.body),
    server_file: 'server.js v8.0',
    timestamp: new Date().toISOString(),
  });
});

// ═══════════════════════════════════════════════════════════════
// API /api/validate-files — Valida que .cer + .key + password
// formen una FIEL valida. NO consulta al SAT, solo valida local.
// ═══════════════════════════════════════════════════════════════
app.post('/api/validate-files', authMiddleware, async (req, res) => {
  const debug = { build_id: BUILD_ID, stage: 'request_received' };
  console.log('[sat-connector] POST /api/validate-files recibido');

  try {
    const { cerBase64, keyBase64, password } = req.body;

    if (!cerBase64 || !keyBase64) {
      return res.status(400).json({
        success: false,
        error: 'Faltan cerBase64 y/o keyBase64',
        error_stage: 'validate-files:missing_params',
        error_classification: 'validation_error',
        safe_debug: safeStageLog('validate-files:missing_params', {}),
      });
    }

    // ─── Etapa: decodificar base64 ───
    debug.stage = 'validate-files:base64_decode';
    let cerBytes, keyBytes;
    try {
      cerBytes = fromBase64(cerBase64.replace(/[\s\r\n]+/g, ''));
      keyBytes = fromBase64(keyBase64.replace(/[\s\r\n]+/g, ''));
    } catch (e) {
      return res.status(400).json({
        success: false,
        error: 'Error al decodificar base64',
        error_stage: 'validate-files:base64_decode',
        error_classification: 'decoding_error',
        safe_debug: safeStageLog('validate-files:base64_decode_failed', { error: sanitizeError(e) }),
        technical_detail: sanitizeError(e),
      });
    }

    // Detectar PEM y extraer DER
    const cerHead = cerBytes.slice(0, 80).toString('ascii');
    let effCerBytes = cerBytes;
    if (cerHead.includes('-----BEGIN CERTIFICATE-----')) {
      const pemStr = cerBytes.toString('ascii');
      const m = pemStr.match(/-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/);
      if (m?.[1]) effCerBytes = Buffer.from(m[1].replace(/[\s\r\n]+/g, ''), 'base64');
    }

    // ─── Etapa: crear FIEL ───
    debug.stage = 'validate-files:create_fiel';
    let fiel;
    try {
      fiel = Fiel.create(effCerBytes.toString('binary'), keyBytes.toString('binary'), password || '');
    } catch (e) {
      const errMsg = sanitizeError(e);
      const isPasswordErr = errMsg.toLowerCase().includes('password') || errMsg.toLowerCase().includes('decrypt') || errMsg.toLowerCase().includes('bad decrypt');
      return res.status(400).json({
        success: false,
        error: isPasswordErr ? 'Contraseña incorrecta para la llave privada' : 'Error al crear FIEL',
        error_stage: 'validate-files:create_fiel',
        error_classification: isPasswordErr ? 'invalid_password' : 'fiel_creation_error',
        safe_debug: safeStageLog('validate-files:create_fiel_failed', { cer_size: effCerBytes.length, key_size: keyBytes.length, is_password_error: isPasswordErr, cer_format: cerHead.includes('-----BEGIN') ? 'PEM' : 'DER' }),
        technical_detail: errMsg,
      });
    }

    // ─── Etapa: validar FIEL ───
    debug.stage = 'validate-files:validate_fiel';
    const isValid = fiel.isValid();
    if (!isValid) {
      return res.status(400).json({
        success: false,
        error: 'FIEL invalida (certificado + llave no coinciden o estan vencidos)',
        error_stage: 'validate-files:validate_fiel',
        error_classification: 'fiel_invalid',
        safe_debug: safeStageLog('validate-files:fiel_invalid', { fiel_valid: false, cer_size: effCerBytes.length, key_size: keyBytes.length }),
        technical_detail: 'fiel.isValid() = false',
      });
    }

    // ─── Etapa: extraer info del certificado ───
    debug.stage = 'validate-files:cert_info';
    let certInfo = { rfc: '', validFrom: '', validTo: '', serialNumber: '' };
    try {
      const { Certificate } = require('@nodecfdi/credentials');
      const cert = Certificate.createFromBase64(cerBase64.replace(/[\s\r\n]+/g, ''));
      certInfo = {
        rfc: cert.rfc(),
        validFrom: cert.validFrom().toISOString(),
        validTo: cert.validTo().toISOString(),
        serialNumber: cert.serialNumber().bytes(),
      };
    } catch (e) {
      // No bloqueante — info del cert es opcional
      certInfo.rfc = 'unknown';
    }

    return res.status(200).json({
      success: true,
      message: 'FIEL validada correctamente',
      data: {
        rfc: certInfo.rfc,
        valid_from: certInfo.validFrom,
        valid_to: certInfo.validTo,
        serial: certInfo.serialNumber,
        fiel_valid: true,
      },
      safe_debug: safeStageLog('validate-files:completed', { fiel_valid: true, rfc_prefix: certInfo.rfc.slice(0, 4) + '****', cer_format: cerHead.includes('-----BEGIN') ? 'PEM' : 'DER' }),
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: 'Error interno del conector SAT',
      error_stage: 'validate-files:exception',
      error_classification: 'connector_internal',
      safe_debug: safeStageLog('validate-files:exception', { error: sanitizeError(err), stack: sanitizeStack(err) }),
      technical_detail: sanitizeError(err),
    });
  }
});

// ═══════════════════════════════════════════════════════════════
// API /api/query — Consulta SAT DescargaMasiva (oficial)
// Body: { cerBase64, keyBase64, password, rfc, dateFrom, dateTo, cfdiType }
// ═══════════════════════════════════════════════════════════════
function buildSatQueryHandler(endpointPath) {
  return async (req, res) => {
    const startTime = Date.now();
    const debug = { build_id: BUILD_ID, stage: 'request_received', endpoint: endpointPath };
    console.log(`[sat-connector] POST ${endpointPath} recibido`);

    try {
      const { cerBase64, keyBase64, password, rfc, dateFrom, dateTo, cfdiType } = req.body;

      // ─── required_fields_validated ───
      debug.stage = 'required_fields_validated';
      if (!cerBase64 || !keyBase64 || !password || !rfc || !dateFrom || !dateTo || !cfdiType) {
        return res.status(400).json({
          success: false,
          error: 'Faltan parametros requeridos',
          error_stage: 'query:missing_params',
          error_classification: 'validation_error',
          safe_debug: safeStageLog('query:missing_params', { has_cer: !!cerBase64, has_key: !!keyBase64, has_password: !!password, has_rfc: !!rfc, has_dates: !!(dateFrom && dateTo), has_type: !!cfdiType }),
          technical_detail: 'Se requiere: cerBase64, keyBase64, password, rfc, dateFrom, dateTo, cfdiType',
        });
      }

      // ─── base64_conversion ───
      debug.stage = 'base64_conversion';
      let cerBytes, keyBytes;
      try {
        cerBytes = fromBase64(cerBase64.replace(/[\s\r\n]+/g, ''));
        keyBytes = fromBase64(keyBase64.replace(/[\s\r\n]+/g, ''));
      } catch (e) {
        return res.status(400).json({
          success: false, error: 'Error al decodificar base64',
          error_stage: 'query:base64_decode', error_classification: 'decoding_error',
          safe_debug: safeStageLog('query:base64_decode_failed', { error: sanitizeError(e) }),
          technical_detail: sanitizeError(e),
        });
      }

      const cerHead = cerBytes.slice(0, 80).toString('ascii');
      let effCerBytes = cerBytes;
      if (cerHead.includes('-----BEGIN CERTIFICATE-----')) {
        const pemStr = cerBytes.toString('ascii');
        const m = pemStr.match(/-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/);
        if (m?.[1]) effCerBytes = Buffer.from(m[1].replace(/[\s\r\n]+/g, ''), 'base64');
      }

      // ─── fiel_creation_start ───
      debug.stage = 'fiel_creation_start';
      let fiel;
      try {
        fiel = Fiel.create(effCerBytes.toString('binary'), keyBytes.toString('binary'), password);
      } catch (e) {
        return res.status(400).json({
          success: false, error: 'Error al crear FIEL',
          error_stage: 'query:fiel_creation', error_classification: 'fiel_creation_error',
          safe_debug: safeStageLog('query:fiel_creation_failed', { error: sanitizeError(e), cer_size: effCerBytes.length, key_size: keyBytes.length }),
          technical_detail: sanitizeError(e),
        });
      }
      debug.stage = 'fiel_creation_success';

      if (!fiel.isValid()) {
        return res.status(400).json({
          success: false, error: 'FIEL invalida',
          error_stage: 'query:fiel_validation', error_classification: 'fiel_invalid',
          safe_debug: safeStageLog('query:fiel_invalid', { fiel_valid: false }),
          technical_detail: 'fiel.isValid() = false',
        });
      }

      // ─── service_creation_start ───
      debug.stage = 'service_creation_start';
      const requestBuilder = new FielRequestBuilder(fiel);
      const webClient = new HttpsWebClient();
      const service = new Service(requestBuilder, webClient);
      debug.stage = 'service_creation_success';

      // ─── parameters_build_start ───
      debug.stage = 'parameters_build_start';
      const period = DateTimePeriod.createFromValues(`${dateFrom} 00:00:00`, `${dateTo} 23:59:59`);
      // v8.0: Usar constructor seguro new DownloadType(...) en lugar de .issued()/.received()
      let downloadType;
      try {
        downloadType = new DownloadType(cfdiType);
      } catch {
        try { downloadType = DownloadType[cfdiType] ? DownloadType[cfdiType]() : new DownloadType(cfdiType); } catch (e2) {
          return res.status(400).json({
            success: false, error: `Tipo de CFDI no soportado: ${cfdiType}`,
            error_stage: 'query:parameters_build', error_classification: 'invalid_cfdi_type',
            safe_debug: safeStageLog('query:invalid_cfdi_type', { cfdiType }),
            technical_detail: sanitizeError(e2),
          });
        }
      }
      const parameters = QueryParameters.create(period, { downloadType });
      debug.stage = 'parameters_build_success';

      // ─── service_query_start ───
      debug.stage = 'service_query_start';
      const query = await service.query(parameters);
      debug.stage = 'service_query_success';

      // ─── response_parsed ───
      debug.stage = 'response_parsed';
      const status = query.getStatus();
      const requestId = query.getRequestId();

      debug.sat_code = status.getCode();
      debug.sat_message = status.getMessage();
      debug.duration_ms = Date.now() - startTime;

      if (!status.isAccepted()) {
        const { faultCode, faultString } = extractSatFaultDetails(status.getMessage());
        return res.status(200).json({
          success: false,
          error: 'No se pudo crear la solicitud de descarga ante el SAT',
          error_stage: 'query:sat_rejected',
          error_classification: faultCode?.includes('InvalidSecurity') ? 'sat_auth_invalid_security' : 'sat_query_rejected',
          detail: status.getMessage(),
          sat_code: status.getCode(),
          sat_message: status.getMessage(),
          fault_code: faultCode,
          fault_string: faultString,
          safe_debug: safeStageLog('query:sat_rejected', { sat_code: status.getCode(), fault_code: faultCode, rfc_prefix: (rfc || '').slice(0, 4) + '****', cfdi_type: cfdiType }),
        });
      }

      if (!requestId || requestId.length < 5) {
        return res.status(200).json({
          success: false,
          error: 'No se pudo crear la solicitud de descarga ante el SAT',
          error_stage: 'query:no_request_id',
          error_classification: 'sat_query_no_id',
          safe_debug: safeStageLog('query:no_request_id', { request_id_empty: !requestId }),
          technical_detail: 'SAT acepto pero no devolvio IdSolicitud valido',
        });
      }

      return res.status(200).json({
        success: true,
        data: {
          requestId,
          sat_code: status.getCode(),
          sat_message: status.getMessage(),
          cfdi_type: cfdiType,
          rfc,
          date_from: dateFrom,
          date_to: dateTo,
        },
        safe_debug: safeStageLog('query:completed', { request_id_prefix: requestId.slice(0, 8) + '...', sat_code: status.getCode(), duration_ms: debug.duration_ms, cfdi_type: cfdiType, rfc_prefix: (rfc || '').slice(0, 4) + '****' }),
      });
    } catch (err) {
      const errMsg = sanitizeError(err);
      const errStack = sanitizeStack(err);
      const { faultCode, faultString } = extractSatFaultDetails(err);

      let errorStage = 'query:exception';
      let errorClassification = 'connector_internal';
      let safeMessage = 'Error interno del conector SAT';

      if (faultCode?.includes('InvalidSecurity') || (faultString || '').includes('verifying security')) {
        errorStage = 'query:ws_security_error';
        errorClassification = 'sat_auth_invalid_security';
        safeMessage = 'No se pudo crear la solicitud de descarga ante el SAT';
      }

      return res.status(500).json({
        success: false,
        error: safeMessage,
        error_stage: errorStage,
        error_classification: errorClassification,
        fault_code: faultCode,
        fault_string: faultString,
        safe_debug: safeStageLog(errorStage, { error: errMsg, fault_code: faultCode, duration_ms: Date.now() - startTime }),
        technical_detail: errStack || errMsg,
      });
    }
  };
}

// ─── POST /api/query (oficial) ───
app.post('/api/query', authMiddleware, buildSatQueryHandler('/api/query'));

// ─── POST /query (legado — compatibilidad) ───
app.post('/query', authMiddleware, async (req, res) => {
  const startTime = Date.now();
  const debug = { build_id: BUILD_ID, stage: 'start', endpoint: '/query (legacy)' };
  console.log('[sat-connector] POST /query recibido (legacy)');

  try {
    const { cerBase64, keyBase64, password, rfc, dateFrom, dateTo, cfdiType } = req.body;

    if (!cerBase64 || !keyBase64 || !password || !rfc || !dateFrom || !dateTo || !cfdiType) {
      return res.status(400).json({ success: false, error: 'Faltan parametros requeridos', detail: 'Se requiere: cerBase64, keyBase64, password, rfc, dateFrom, dateTo, cfdiType' });
    }

    let cerBytes, keyBytes;
    try { cerBytes = fromBase64(cerBase64.replace(/[\s\r\n]+/g, '')); keyBytes = fromBase64(keyBase64.replace(/[\s\r\n]+/g, '')); }
    catch (e) { return res.status(400).json({ success: false, error: 'Error al decodificar base64', detail: sanitizeError(e), debug }); }

    const cerHead = cerBytes.slice(0, 80).toString('ascii');
    let effCerBytes = cerBytes;
    if (cerHead.includes('-----BEGIN CERTIFICATE-----')) {
      const pemStr = cerBytes.toString('ascii');
      const m = pemStr.match(/-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/);
      if (m?.[1]) effCerBytes = Buffer.from(m[1].replace(/[\s\r\n]+/g, ''), 'base64');
    }

    debug.stage = 'creating_fiel';
    let fiel;
    try { fiel = Fiel.create(effCerBytes.toString('binary'), keyBytes.toString('binary'), password); }
    catch (e) { debug.stage = 'fiel_create_failed'; debug.error = sanitizeError(e); return res.status(400).json({ success: false, error: 'Error al crear FIEL', detail: sanitizeError(e), debug }); }

    if (!fiel.isValid()) {
      return res.status(400).json({ success: false, error: 'FIEL invalida', detail: 'fiel.isValid() = false', debug });
    }

    debug.stage = 'creating_service';
    const requestBuilder = new FielRequestBuilder(fiel);
    const webClient = new HttpsWebClient();
    const service = new Service(requestBuilder, webClient);

    debug.stage = 'building_params';
    const period = DateTimePeriod.createFromValues(`${dateFrom} 00:00:00`, `${dateTo} 23:59:59`);
    const downloadType = cfdiType === 'issued' ? DownloadType.issued() : DownloadType.received();
    const parameters = QueryParameters.create(period, { downloadType });

    debug.stage = 'executing_query';
    const query = await service.query(parameters);
    const status = query.getStatus();
    debug.duration_ms = Date.now() - startTime;

    if (!status.isAccepted()) {
      const { faultCode, faultString } = extractSatFaultDetails(status.getMessage());
      return res.status(200).json({ success: false, error: 'SAT rechazo la solicitud', detail: status.getMessage(), sat_code: status.getCode(), sat_message: status.getMessage(), fault_code: faultCode, fault_string: faultString, debug });
    }

    const requestId = query.getRequestId();
    if (!requestId || requestId.length < 5) {
      return res.status(200).json({ success: false, error: 'SAT acepto pero no devolvio IdSolicitud valido', detail: 'requestId vacio o muy corto', debug });
    }

    return res.status(200).json({ success: true, data: { requestId, sat_code: status.getCode(), sat_message: status.getMessage(), cfdi_type: cfdiType, rfc, date_from: dateFrom, date_to: dateTo }, debug });
  } catch (err) {
    debug.stage = 'exception'; debug.error = sanitizeError(err); debug.duration_ms = Date.now() - startTime;
    const { faultCode, faultString } = extractSatFaultDetails(err);
    return res.status(500).json({ success: false, error: 'Error interno del conector SAT', detail: sanitizeError(err), debug });
  }
});

// ═══════════════════════════════════════════════════════════════
// API /api/verify — VerificaSolicitudDescarga (oficial)
// Body: { cerBase64, keyBase64, password, rfc, requestId }
// ═══════════════════════════════════════════════════════════════
function buildSatVerifyHandler(endpointPath) {
  return async (req, res) => {
    const startTime = Date.now();
    const debug = { build_id: BUILD_ID, stage: 'request_received', endpoint: endpointPath };
    console.log(`[sat-connector] POST ${endpointPath} recibido`);

    try {
      const { cerBase64, keyBase64, password, rfc, requestId } = req.body;

      if (!cerBase64 || !keyBase64 || !password || !rfc || !requestId) {
        return res.status(400).json({
          success: false,
          error: 'Faltan parametros requeridos',
          error_stage: 'verify:missing_params',
          error_classification: 'validation_error',
          safe_debug: safeStageLog('verify:missing_params', { has_cer: !!cerBase64, has_key: !!keyBase64, has_password: !!password, has_rfc: !!rfc, has_request_id: !!requestId }),
          technical_detail: 'Se requiere: cerBase64, keyBase64, password, rfc, requestId',
        });
      }

      // Decode
      debug.stage = 'verify:decoding';
      const cerBytes = fromBase64(cerBase64.replace(/[\s\r\n]+/g, ''));
      const keyBytes = fromBase64(keyBase64.replace(/[\s\r\n]+/g, ''));

      const cerHead = cerBytes.slice(0, 80).toString('ascii');
      let effCerBytes = cerBytes;
      if (cerHead.includes('-----BEGIN CERTIFICATE-----')) {
        const pemStr = cerBytes.toString('ascii');
        const m = pemStr.match(/-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/);
        if (m?.[1]) effCerBytes = Buffer.from(m[1].replace(/[\s\r\n]+/g, ''), 'base64');
      }

      // FIEL
      debug.stage = 'verify:creating_fiel';
      const fiel = Fiel.create(effCerBytes.toString('binary'), keyBytes.toString('binary'), password);

      if (!fiel.isValid()) {
        return res.status(400).json({
          success: false, error: 'FIEL invalida',
          error_stage: 'verify:fiel_invalid', error_classification: 'fiel_invalid',
          safe_debug: safeStageLog('verify:fiel_invalid', { fiel_valid: false, request_id_prefix: requestId.slice(0, 8) + '...' }),
          technical_detail: 'fiel.isValid() = false',
        });
      }

      // Service
      debug.stage = 'verify:creating_service';
      const requestBuilder = new FielRequestBuilder(fiel);
      const webClient = new HttpsWebClient();
      const service = new Service(requestBuilder, webClient);

      // Verify
      debug.stage = 'verify:executing';
      const verifyResult = await service.verify(requestId);
      debug.stage = 'verify:response_received';
      const status = verifyResult.getStatus();

      debug.sat_code = status.getCode();
      debug.sat_message = status.getMessage();
      debug.duration_ms = Date.now() - startTime;

      const isReady = status.getCode() === 5000;
      const packages = [];
      let numCfdis = 0;
      try {
        for (const pkg of verifyResult.getPackages()) {
          packages.push(pkg.get('id'));
        }
      } catch { /* fallback */ }
      try { numCfdis = verifyResult.countCfdis(); } catch { /* fallback */ }

      const responseData = {
        requestId,
        packagesReady: isReady,
        numCfdis,
        packageIds: packages,
        packageCount: packages.length,
        sat_code: status.getCode(),
        sat_message: status.getMessage(),
      };

      if (isReady) {
        return res.status(200).json({
          success: true,
          data: responseData,
          safe_debug: safeStageLog('verify:packages_ready', { packages_count: packages.length, num_cfdis: numCfdis, sat_code: status.getCode(), duration_ms: debug.duration_ms, request_id_prefix: requestId.slice(0, 8) + '...' }),
        });
      }

      // still_processing o rejected
      const isRejected = status.getCode() !== 5000 && status.getCode() !== 5001 && status.getCode() !== 5002;
      return res.status(200).json({
        success: false,
        error: isRejected ? 'SAT rechazo la verificacion' : 'SAT aun esta procesando la solicitud',
        error_stage: isRejected ? 'verify:rejected_by_sat' : 'verify:still_processing',
        error_classification: isRejected ? 'sat_verify_rejected' : 'still_processing',
        data: responseData,
        detail: status.getMessage(),
        safe_debug: safeStageLog(isRejected ? 'verify:rejected_by_sat' : 'verify:still_processing', { sat_code: status.getCode(), sat_message: status.getMessage(), request_id_prefix: requestId.slice(0, 8) + '...' }),
      });
    } catch (err) {
      const errMsg = sanitizeError(err);
      return res.status(500).json({
        success: false,
        error: 'No se pudo verificar la disponibilidad de paquetes',
        error_stage: 'verify:exception',
        error_classification: 'connector_internal',
        safe_debug: safeStageLog('verify:exception', { error: errMsg, duration_ms: Date.now() - startTime }),
        technical_detail: sanitizeStack(err) || errMsg,
      });
    }
  };
}

// ─── POST /api/verify (oficial) ───
app.post('/api/verify', authMiddleware, buildSatVerifyHandler('/api/verify'));

// ─── POST /verify (legado — compatibilidad) ───
app.post('/verify', authMiddleware, async (req, res) => {
  const startTime = Date.now();
  const debug = { stage: 'start' };
  console.log('[sat-connector] POST /verify recibido (legacy)');

  try {
    const { cerBase64, keyBase64, password, rfc, requestId } = req.body;

    if (!cerBase64 || !keyBase64 || !password || !rfc || !requestId) {
      return res.status(400).json({ success: false, error: 'Faltan parametros requeridos', detail: 'Se requiere: cerBase64, keyBase64, password, rfc, requestId' });
    }

    const cerBytes = fromBase64(cerBase64.replace(/[\s\r\n]+/g, ''));
    const keyBytes = fromBase64(keyBase64.replace(/[\s\r\n]+/g, ''));

    const cerHead = cerBytes.slice(0, 80).toString('ascii');
    let effCerBytes = cerBytes;
    if (cerHead.includes('-----BEGIN CERTIFICATE-----')) {
      const pemStr = cerBytes.toString('ascii');
      const m = pemStr.match(/-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/);
      if (m?.[1]) effCerBytes = Buffer.from(m[1].replace(/[\s\r\n]+/g, ''), 'base64');
    }

    const fiel = Fiel.create(effCerBytes.toString('binary'), keyBytes.toString('binary'), password);
    if (!fiel.isValid()) return res.status(400).json({ success: false, error: 'FIEL invalida', debug });

    const requestBuilder = new FielRequestBuilder(fiel);
    const webClient = new HttpsWebClient();
    const service = new Service(requestBuilder, webClient);

    debug.stage = 'executing_verify';
    const verifyResult = await service.verify(requestId);
    const status = verifyResult.getStatus();

    debug.sat_code = status.getCode();
    debug.sat_message = status.getMessage();
    debug.duration_ms = Date.now() - startTime;

    const packages = [];
    try { for (const pkg of verifyResult.getPackages()) { packages.push(pkg.get('id')); } } catch {}
    let numCfdis = 0;
    try { numCfdis = verifyResult.countCfdis(); } catch {}

    return res.status(200).json({
      success: true,
      data: { requestId, packagesReady: status.getCode() === 5000, numCfdis, packageIds: packages, packageCount: packages.length, sat_code: status.getCode(), sat_message: status.getMessage() },
      debug,
    });
  } catch (err) {
    debug.stage = 'exception'; debug.error = sanitizeError(err); debug.duration_ms = Date.now() - startTime;
    return res.status(500).json({ success: false, error: 'Error al verificar solicitud SAT', detail: sanitizeError(err), debug });
  }
});

// ═══════════════════════════════════════════════════════════════
// API /api/download — Descargar paquete SAT (oficial)
// Body: { cerBase64, keyBase64, password, rfc, packageId }
// ═══════════════════════════════════════════════════════════════
app.post('/api/download', authMiddleware, async (req, res) => {
  const startTime = Date.now();
  const debug = { build_id: BUILD_ID, stage: 'request_received' };
  console.log('[sat-connector] POST /api/download recibido');

  try {
    const { cerBase64, keyBase64, password, rfc, packageId } = req.body;

    if (!cerBase64 || !keyBase64 || !password || !rfc || !packageId) {
      return res.status(400).json({
        success: false,
        error: 'Faltan parametros requeridos',
        error_stage: 'download:missing_params',
        error_classification: 'validation_error',
        safe_debug: safeStageLog('download:missing_params', { has_cer: !!cerBase64, has_key: !!keyBase64, has_password: !!password, has_rfc: !!rfc, has_package_id: !!packageId }),
        technical_detail: 'Se requiere: cerBase64, keyBase64, password, rfc, packageId',
      });
    }

    // Decode
    debug.stage = 'download:decoding';
    const cerBytes = fromBase64(cerBase64.replace(/[\s\r\n]+/g, ''));
    const keyBytes = fromBase64(keyBase64.replace(/[\s\r\n]+/g, ''));

    const cerHead = cerBytes.slice(0, 80).toString('ascii');
    let effCerBytes = cerBytes;
    if (cerHead.includes('-----BEGIN CERTIFICATE-----')) {
      const pemStr = cerBytes.toString('ascii');
      const m = pemStr.match(/-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/);
      if (m?.[1]) effCerBytes = Buffer.from(m[1].replace(/[\s\r\n]+/g, ''), 'base64');
    }

    // FIEL
    debug.stage = 'download:creating_fiel';
    const fiel = Fiel.create(effCerBytes.toString('binary'), keyBytes.toString('binary'), password);
    if (!fiel.isValid()) {
      return res.status(400).json({
        success: false, error: 'FIEL invalida',
        error_stage: 'download:fiel_invalid', error_classification: 'fiel_invalid',
        safe_debug: safeStageLog('download:fiel_invalid', { package_id_prefix: packageId.slice(0, 8) + '...' }),
        technical_detail: 'fiel.isValid() = false',
      });
    }

    // Service
    debug.stage = 'download:creating_service';
    const requestBuilder = new FielRequestBuilder(fiel);
    const webClient = new HttpsWebClient();
    const service = new Service(requestBuilder, webClient);

    // Download
    debug.stage = 'download:executing';
    const downloadResult = await service.download(packageId);
    debug.stage = 'download:received';

    const zipBuffer = downloadResult.getPackageContent();
    if (!zipBuffer || zipBuffer.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No se pudieron descargar los paquetes del SAT',
        error_stage: 'download:empty_package',
        error_classification: 'package_download_failed',
        safe_debug: safeStageLog('download:empty_package', { package_id_prefix: packageId.slice(0, 8) + '...', buffer_empty: true }),
        technical_detail: 'getPackageContent() devolvio buffer vacio',
      });
    }

    debug.stage = 'download:completed';
    debug.duration_ms = Date.now() - startTime;
    debug.zip_size = zipBuffer.length;

    // Devolver ZIP como base64
    const zipBase64 = Buffer.from(zipBuffer).toString('base64');

    return res.status(200).json({
      success: true,
      data: {
        packageId,
        zipBase64,
        zipSize: zipBuffer.length,
      },
      safe_debug: safeStageLog('download:completed', { package_id_prefix: packageId.slice(0, 8) + '...', zip_size: zipBuffer.length, zip_size_kb: Math.round(zipBuffer.length / 1024), duration_ms: debug.duration_ms }),
    });
  } catch (err) {
    const errMsg = sanitizeError(err);
    return res.status(500).json({
      success: false,
      error: 'No se pudieron descargar los paquetes del SAT',
      error_stage: 'download:exception',
      error_classification: 'connector_internal',
      safe_debug: safeStageLog('download:exception', { error: errMsg, duration_ms: Date.now() - startTime }),
      technical_detail: sanitizeStack(err) || errMsg,
    });
  }
});

// ─── POST /cert-info ───
app.post('/cert-info', authMiddleware, async (req, res) => {
  console.log('[sat-connector] POST /cert-info recibido');
  try {
    const { Certificate } = require('@nodecfdi/credentials');
    const { cerBase64 } = req.body;
    if (!cerBase64) return res.status(400).json({ success: false, error: 'Falta cerBase64' });
    const cert = Certificate.createFromBase64(cerBase64.replace(/[\s\r\n]+/g, ''));
    return res.status(200).json({ success: true, data: { serialNumber: cert.serialNumber().bytes(), validFrom: cert.validFrom().toISOString(), validTo: cert.validTo().toISOString(), rfc: cert.rfc() } });
  } catch (err) {
    return res.status(400).json({ success: false, error: 'Error al leer certificado', detail: sanitizeError(err) });
  }
});

// ─── CATCH-ALL 404 ───
app.use((req, res) => {
  console.log(`[sat-connector] 404 - Route not found: ${req.method} ${req.path}`);
  res.status(404).json({
    success: false,
    error: 'Route not found',
    build_id: BUILD_ID,
    path: req.path,
    method: req.method,
    available_routes: [
      { method: 'GET', path: '/' }, { method: 'GET', path: '/version' }, { method: 'GET', path: '/routes' },
      { method: 'GET', path: '/health' }, { method: 'POST', path: '/echo' },
      { method: 'POST', path: '/query' }, { method: 'POST', path: '/verify' }, { method: 'POST', path: '/cert-info' },
      { method: 'POST', path: '/api/validate-files' }, { method: 'POST', path: '/api/query' },
      { method: 'POST', path: '/api/verify' }, { method: 'POST', path: '/api/download' },
    ],
  });
});

// ─── START ───
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[sat-connector] === SERVIDOR CORRIENDO ===`);
  console.log(`[sat-connector] BUILD_ID: ${BUILD_ID}`);
  console.log(`[sat-connector] Puerto: ${PORT}`);
  console.log(`[sat-connector] Node.js: ${process.version}`);
  console.log(`[sat-connector] Express: ${require('express/package.json').version}`);
  console.log(`[sat-connector] =============================`);
});