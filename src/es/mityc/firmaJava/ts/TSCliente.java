/**
 * LICENCIA LGPL:
 * 
 * Esta librería es Software Libre; Usted puede redistribuirlo y/o modificarlo
 * bajo los términos de la GNU Lesser General Public License (LGPL)
 * tal y como ha sido publicada por la Free Software Foundation; o
 * bien la versión 2.1 de la Licencia, o (a su elección) cualquier versión posterior.
 * 
 * Esta librería se distribuye con la esperanza de que sea útil, pero SIN NINGUNA
 * GARANTÍA; tampoco las implícitas garantías de MERCANTILIDAD o ADECUACIÓN A UN
 * PROPÓSITO PARTICULAR. Consulte la GNU Lesser General Public License (LGPL) para más
 * detalles
 * 
 * Usted debe recibir una copia de la GNU Lesser General Public License (LGPL)
 * junto con esta librería; si no es así, escriba a la Free Software Foundation Inc.
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA o consulte
 * <http://www.gnu.org/licenses/>.
 *
 * Copyright 2008 Ministerio de Industria, Turismo y Comercio
 * 
 */

package es.mityc.firmaJava.ts;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

import es.mityc.javasign.ssl.ISSLManager;

/**
 * <p>Clase encargada de generar sellos de tiempo.</p>
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class TSCliente {
    
	/** Servidor que da el servicio de sellado de tiempo. */
	private String servidorTSA = null;
	/** Algoritmo hash del sello de tiempo. */
	private String algoritmoHash = null;
	/** Cliente Http para las comunicaciones. */    
//	private static final HttpClient CLIENTE = new HttpClient(); 
	/** Valor 5000 para timeouts. */
//	private static final Integer INT5000 = new Integer(5000);
	/** Looger. */
	static Log log = LogFactory.getLog(TSCliente.class.getName());
    
    /**
     * <p>Crea una nueva instancia de TSCliente.</p>
     * @param nombreServidor Nombre del servidor
     * @param algoritmoHash Algoritmo del hash del Sello de Tiempo
     */
	public TSCliente(final String nombreServidor, final String algoritmoHash) {
		super();
		this.servidorTSA = nombreServidor;        

		// Algoritmo para digest aceptado por defecto
		this.algoritmoHash = ConstantesTSA.SHA1;

		// Comprueba que el algoritmo configurado en propiedades es aceptado. Si no lo es deja el algoritmo por defecto.
		// Los algoritmos aceptados se pueden ver en la clase TSPAlgorithms (excepto MD5)
		if (algoritmoHash != null) {
			String temp = algoritmoHash.trim().toUpperCase();
			if (TSPAlgoritmos.getPermitidos().contains(algoritmoHash)) {
				this.algoritmoHash = temp;
			} else {
				log.warn(ConstantesTSA.MENSAJE_NO_ALGORITMO_HASH);
			}
		}
	}
	
//	/**
//	 * <p>Establece un gestionador de las conexiones SSL para el cliente.</p>
//	 * @param sslmanager Gestionador de las conexiones SSL
//	 */
//	public static void setSSLManager(ISSLManager sslmanager) {
//		Protocol authhttps = new Protocol("https", new OwnSSLProtocolSocketFactory(sslmanager), 443); 
//		Protocol.registerProtocol("https", authhttps);
//	}
    
    /**
     * <p>Este método genera el Sello de Tiempo.</p>
     * @param binarioaSellar fichero binario que se va a sellar
     * @return TimeStampToken en formato binario
     * @throws TSClienteError En caso de error
     */
    public byte[] generarSelloTiempo(final byte[] binarioaSellar) throws TSClienteError {
    	
    	log.info("generarSelloTiempo inicio");
    	
        if (binarioaSellar == null) {
        	log.error(ConstantesTSA.MENSAJE_NO_DATOS_SELLO_TIEMPO);
            throw new TSClienteError(I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_1));
            
        } else {
            log.info(ConstantesTSA.MENSAJE_GENERANDO_SELLO_TIEMPO);
            TimeStampRequestGenerator generadorPeticion = new TimeStampRequestGenerator();
            generadorPeticion.setCertReq(true);
            TimeStampRequest peticion = null;
            TimeStampResponse respuesta = null;
            
            try {
                MessageDigest resumen = MessageDigest.getInstance(algoritmoHash);
                resumen.update(binarioaSellar);
                peticion = generadorPeticion.generate(TSPAlgoritmos.getOID(algoritmoHash), resumen.digest());
                log.info(ConstantesTSA.MENSAJE_PETICION_TSA_GENERADA);
            } catch (final Exception e) {
                log.error(ConstantesTSA.MENSAJE_ERROR_PETICION_TSA, e);
                throw new TSClienteError(I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_10));                
            }
            
            
//          // httpclient
//            CLIENTE.getParams().setParameter(HttpClientParams.SO_TIMEOUT, INT5000);
//
//            String servidorProxy = System.getProperty("http.proxyHost");
//            log.info("servidorProxy: " + servidorProxy);
//            if (servidorProxy != null) {
//            	int puertoProxy = 80;
//            	try {
//            		puertoProxy = Integer.parseInt(System.getProperty("http.proxyPort"));
//            		log.info("puertoProxy: " + puertoProxy);
//            	} catch (NumberFormatException ex) { }
//            	CLIENTE.getHostConfiguration().setProxy(servidorProxy, puertoProxy);
//            	
//        		Credentials defaultcreds = new AuthenticatorProxyCredentials(servidorProxy, ConstantesTSA.CADENA_VACIA);
//        		log.info("credentials userName: " + ((AuthenticatorProxyCredentials)defaultcreds).getUserName());
//        		log.info("credentials password: " + ((AuthenticatorProxyCredentials)defaultcreds).getPassword());
//        		CLIENTE.getState().setProxyCredentials(AuthScope.ANY, defaultcreds);
//            }
            
            // TODO alfredo borrar esto
			// pruebas proxy selector con httpclient
//            try {
//				ProxySelector ps = ProxySelector.getDefault();
//				log.info("servidorTSA: " + servidorTSA);
//				List<Proxy> proxyList = ps.select(new URI(servidorTSA));
//				Proxy proxy = proxyList.get(0);
//
//				if (proxy != null) {
//					String proxyHost = null;
//					int proxyPort = 80;
//					
//					InetSocketAddress addr = ((InetSocketAddress) proxy.address());
//					if (addr != null) {
//						proxyHost = addr.getHostName();
//						proxyPort = addr.getPort();
//					}
//					log.info("proxyHost: " + proxyHost);
//					log.info("proxyPort: " + proxyPort);
//
//					if (proxyHost != null && proxyHost.length() > 0) {
//						CLIENTE.getHostConfiguration().setProxy(proxyHost, proxyPort);
//						// Authenticator
//						Credentials defaultcreds = new AuthenticatorProxyCredentials(proxyHost, ConstantesTSA.CADENA_VACIA);
//		        		CLIENTE.getState().setProxyCredentials(AuthScope.ANY, defaultcreds);
//					}			
//				}
//				
//            } catch (URISyntaxException e) {
//            	log.info("error al establecer el proxy para la conexion", e);
//			}
			// pruebas proxy selector con httpclient end

        

//            PostMethod metodo = new PostMethod(servidorTSA);
//            metodo.addRequestHeader(ConstantesTSA.CONTENT_TYPE, ConstantesTSA.APPLICATION_TIMESTAMP_QUERY);
//            ByteArrayInputStream datos = null;
//            try {
//                datos = new ByteArrayInputStream(peticion.getEncoded());
//            } catch (IOException e) {
//                log.error(ConstantesTSA.MENSAJE_ERROR_PETICION + e.getMessage(), e);
//                throw new TSClienteError(I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_11) + ConstantesTSA.DOS_PUNTOS_ESPACIO + e.getMessage());
//            }
//            
//            InputStreamRequestEntity rq = new InputStreamRequestEntity(datos);
//            metodo.setRequestEntity(rq);
//            
//            metodo.getParams().setParameter(HttpMethodParams.RETRY_HANDLER,
//                    new DefaultHttpMethodRetryHandler(3, false));
//                       
//            byte[] cuerpoRespuesta = null;
//            
//            
//            try {
//                int estadoCodigo = CLIENTE.executeMethod(metodo);
//                log.info(ConstantesTSA.MENSAJE_PETICION_TSA_ENVIADA);
//                
//                if (estadoCodigo != HttpStatus.SC_OK) {                	
//                    log.error(ConstantesTSA.MENSAJE_FALLO_EJECUCION_METODO + metodo.getStatusLine());
//                    throw new TSClienteError(I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_12) + ConstantesTSA.DOS_PUNTOS_ESPACIO + metodo.getStatusLine());
//                }
//                
//                cuerpoRespuesta = metodo.getResponseBody();
//                log.info(ConstantesTSA.MENSAJE_RESPUESTA_TSA_OBTENIDA);
//                
//                try {
//                    respuesta = new TimeStampResponse(cuerpoRespuesta);
//                    try {
//                        
//                    	// Se valida que la respuesta sea la petición enviada
//                    	respuesta.validate(peticion);
//                    	
//                        log.info(ConstantesTSA.MENSAJE_RESPUESTA_TSA_VALIDADA_OK);
//                        // Para solucionar bug en libreria bouncycastle
//                        //return respuesta.getTimeStampToken().getEncoded();
//                        //AppPerfect: Falso positivo
//                        ASN1InputStream is = new ASN1InputStream(cuerpoRespuesta);
//                        ASN1Sequence seq = ASN1Sequence.getInstance(is.readObject());
//                        DEREncodable enc = seq.getObjectAt(1);
//                        if (enc == null) {
//                        	return null;
//                        }
//                        return enc.getDERObject().getEncoded();
//                        //Fin Para solucionar bug en libreria bouncycastle
//                    } catch (TSPException e) {
//                    	
//                    	log.error(ConstantesTSA.MENSAJE_RESPUESTA_NO_VALIDA + e.getMessage(), e);
//                        throw new TSClienteError(I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_9) + ConstantesTSA.DOS_PUNTOS_ESPACIO + e.getMessage());
//                    }
//                } catch (TSPException e) { 
//                	
//                    log.error(ConstantesTSA.MENSAJE_RESPUESTA_MAL_FORMADA + e.getMessage(), e);
//                	throw new TSClienteError(I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_8) + ConstantesTSA.DOS_PUNTOS_ESPACIO + e.getMessage());
//                	
//                } catch (IOException e) {
//                	
//                	log.error(ConstantesTSA.MENSAJE_SECUENCIA_BYTES_MAL_CODIFICADA + e.getMessage(), e);
//                	throw new TSClienteError(I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_7) + ConstantesTSA.DOS_PUNTOS_ESPACIO + e.getMessage());
//                }               
//            } 
//            catch (HttpException e) {
//            	
//                log.error(ConstantesTSA.MENSAJE_VIOLACION_PROTOCOLO_HTTP + e.getMessage(), e);
//            	throw new TSClienteError(I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_6) + ConstantesTSA.DOS_PUNTOS_ESPACIO + e.getMessage());
//            	
//            } catch (IOException e) {
//            	
//            	log.error(ConstantesTSA.MENSAJE_ERROR_CONEXION_SERVIDOR_OCSP + e.getMessage(), e);
//            	String mensajeError = I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_4) + ConstantesTSA.DOS_PUNTOS_ESPACIO + servidorTSA; 
//            	throw new TSClienteError(mensajeError);
//            	
//            } finally {
//                // Termina la conexión
//                metodo.releaseConnection();
//                log.info("generarSelloTiempo fin");
//            }
            
            
            // java
            try {
	            URL url = new URL(servidorTSA);
	            URLConnection tsaConnection;
	            tsaConnection = (URLConnection) url.openConnection();
	            
	            tsaConnection.setDoInput(true);
	            tsaConnection.setDoOutput(true);
	            tsaConnection.setUseCaches(false);
	            tsaConnection.setConnectTimeout(5000);
	            
	            tsaConnection.setRequestProperty(ConstantesTSA.CONTENT_TYPE, ConstantesTSA.APPLICATION_TIMESTAMP_QUERY);
	            //tsaConnection.setRequestProperty("Content-Transfer-Encoding", "base64");
	            tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");
	
//				if ((tsaUsername != null) && !tsaUsername.equals("")) {
//					String userPassword = tsaUsername + ":" + tsaPassword;
//					tsaConnection.setRequestProperty("Authorization", "Basic " + new String(Base64.encodeBytes(userPassword.getBytes())));
//				}
			
				OutputStream out = tsaConnection.getOutputStream();

				out.write(peticion.getEncoded());
				out.close();

				// Get TSA response as a byte array
				InputStream inp = tsaConnection.getInputStream();
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				byte[] buffer = new byte[1024];
				int bytesRead = 0;
				while ((bytesRead = inp.read(buffer, 0, buffer.length)) >= 0) {
					baos.write(buffer, 0, bytesRead);
				}
				byte[] respBytes = baos.toByteArray();

				String encoding = tsaConnection.getContentEncoding();
				if (encoding != null && encoding.equalsIgnoreCase("base64")) {
					respBytes = Base64.decode(new String(respBytes));
				}

				log.info(ConstantesTSA.MENSAJE_RESPUESTA_TSA_OBTENIDA);

				try {
					respuesta = new TimeStampResponse(respBytes);
					try {
						// Se valida que la respuesta sea la petición enviada
						respuesta.validate(peticion);

						log.info(ConstantesTSA.MENSAJE_RESPUESTA_TSA_VALIDADA_OK);
						// Para solucionar bug en libreria bouncycastle
						// return respuesta.getTimeStampToken().getEncoded();
						// AppPerfect: Falso positivo
						ASN1InputStream is = new ASN1InputStream(respBytes);
						ASN1Sequence seq = ASN1Sequence.getInstance(is.readObject());
						DEREncodable enc = seq.getObjectAt(1);
						if (enc == null) {
							return null;
						}
						return enc.getDERObject().getEncoded();
						// Fin Para solucionar bug en libreria bouncycastle
						
					} catch (TSPException e) {

						log.error(ConstantesTSA.MENSAJE_RESPUESTA_NO_VALIDA + e.getMessage(), e);
						throw new TSClienteError(I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_9) + ConstantesTSA.DOS_PUNTOS_ESPACIO
								+ e.getMessage());
					}
				} catch (TSPException e) {

					log.error(ConstantesTSA.MENSAJE_RESPUESTA_MAL_FORMADA + e.getMessage(), e);
					throw new TSClienteError(I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_8) + ConstantesTSA.DOS_PUNTOS_ESPACIO
							+ e.getMessage());

				} catch (IOException e) {

					log.error(ConstantesTSA.MENSAJE_SECUENCIA_BYTES_MAL_CODIFICADA + e.getMessage(), e);
					throw new TSClienteError(I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_7) + ConstantesTSA.DOS_PUNTOS_ESPACIO
							+ e.getMessage());
				}

			} catch (IOException e) {
				
				log.error(ConstantesTSA.MENSAJE_ERROR_CONEXION_SERVIDOR_OCSP + e.getMessage(), e);
				String mensajeError = I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_4) + ConstantesTSA.DOS_PUNTOS_ESPACIO + servidorTSA; 
            	throw new TSClienteError(mensajeError);
				
			}
		}
	     
    }  
    
    
    /**
     * <p>Ejemplo de validacion del sello de tiempo.</p>
     * @param args No se admiten argumentos
     */
    public static void main(final String[] args) {
//    	TSCliente cliente = new TSCliente("http://minister-6vp1kq.mityc.age:9207","SHA-1", null, 0);
//        byte[] firma = Base64.decode(("X1MlQzZRNqBeJR2hjunePlD+ywlkdgaBAo3QDRhItXGhb1k4FffA6V2w5KZoSjPCaDhMgwcTXxz3"+
//        		"UThBmRlOxfZaPCpne63jRlkp63g2IclrmBRKFgsb+Wzb0/pNh/ITffiARrRpYqtO7M92V1+GZbph"+
//        		"m8swQHEJlCtiOyJvwPsFkq5LyB8Zm9pBhUo12oVWnU2sCi9EMl1wIGpr71o7rm0XeudCnFS+45pb"+
//        		"1uQNOILSYizSEnFZpa81/nSgjlW93q0xcE5wrzBsHvUPvhRHydXyYzITXYiSKSFFBuM/N/dcrn57"+
//        "HoaCGoJP6zQ/Wd00c7AopMxM4qFcLSuljIRSag==")) ;
//        byte[] tiempoSello = Base64.decode(("MIAGCSqGSIb3DQEHAqCAMIICdgIBAzELMAkGBSsOAwIaBQAwgZwGCyqGSIb3DQEJEAEEoIGMBIGJMIGGAgEBBgUqAwQFBjAhMAkGBSsOAwIaBQAEFLLvwLC3nEd02gNUWVajJdZXzgCuAhDYJoYNZgUCsQnl459uAPTjGA8yMDA3MDQxODE1MjIyM1qgNKQyMDAxCzAJBgNVBAYTAkVTMQ0wCwYDVQQLEwRERU1PMRIwEAYDVQQDEwlNSVRZQyBUU1AxggHDMIIBvwIBATBEMDAxCzAJBgNVBAYTAkVTMQ0wCwYDVQQLEwRERU1PMRIwEAYDVQQDEwlNSVRZQyBUU1ACEACk/CLM7Wk3DZLGU0wsw+4wCQYFKw4DAhoFAKCB1jAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTA3MDQxODE1MjIyM1owIwYJKoZIhvcNAQkEMRYEFEF7oHc9iR2uGAGjO+rta/Qqy5OpMHUGCyqGSIb3DQEJEAIMMWYwZDBiMGAEFCzqcQksWEIV1+dMt+JE/PEKjp1zMEgwNKQyMDAxCzAJBgNVBAYTAkVTMQ0wCwYDVQQLEwRERU1PMRIwEAYDVQQDEwlNSVRZQyBUU1ACEACk/CLM7Wk3DZLGU0wsw+4wDQYJKoZIhvcNAQEBBQAEgYCMr1HUe8xtsJ+a4cwQoV1DeTarNP4BLpSDM0qQky/ZKJgmsldaIUIG9j246njLAMGBURU1rbi+HhOKbIVImjWk7G/hzn/sUQsgrIqdffoGW5PSnVR5hKBPsTDUvdnZ8LvHLCLbir44TDVhF2ewzjp9lYXjM9/cMNU8cS3vePmftgAAAAA=")) ;
//        TSValidacion tsv = null;
//        try {
//            tsv = cliente.validarSelloTiempo(firma, tiempoSello);
//            
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        }
//        
//        log.info("------------------------------------------");
//        if (tsv != null){
//        	log.info(tsv.getFecha());   
//        }
    }
}

