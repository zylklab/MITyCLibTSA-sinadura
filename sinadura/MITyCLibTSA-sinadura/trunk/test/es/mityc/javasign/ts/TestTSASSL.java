///**
// * LICENCIA LGPL:
// * 
// * Esta librería es Software Libre; Usted puede redistribuirlo y/o modificarlo
// * bajo los términos de la GNU Lesser General Public License (LGPL)
// * tal y como ha sido publicada por la Free Software Foundation; o
// * bien la versión 2.1 de la Licencia, o (a su elección) cualquier versión posterior.
// * 
// * Esta librería se distribuye con la esperanza de que sea útil, pero SIN NINGUNA
// * GARANTÍA; tampoco las implícitas garantías de MERCANTILIDAD o ADECUACIÓN A UN
// * PROPÓSITO PARTICULAR. Consulte la GNU Lesser General Public License (LGPL) para más
// * detalles
// * 
// * Usted debe recibir una copia de la GNU Lesser General Public License (LGPL)
// * junto con esta librería; si no es así, escriba a la Free Software Foundation Inc.
// * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA.
// * 
// */
//package es.mityc.javasign.ts;
//
//import static org.junit.Assert.fail;
//
//import java.io.IOException;
//import java.security.KeyStore;
//import java.security.KeyStoreException;
//import java.security.NoSuchAlgorithmException;
//import java.security.NoSuchProviderException;
//import java.security.UnrecoverableKeyException;
//import java.security.cert.CertStoreException;
//import java.security.cert.CertificateException;
//import java.util.MissingResourceException;
//import java.util.ResourceBundle;
//
//import javax.net.ssl.KeyManagerFactory;
//
//import org.bouncycastle.tsp.TSPException;
//import org.junit.Before;
//import org.junit.Test;
//
//import es.mityc.firmaJava.ts.ConstantesTSA;
//import es.mityc.firmaJava.ts.TSCliente;
//import es.mityc.firmaJava.ts.TSClienteError;
//import es.mityc.firmaJava.ts.TSValidator;
//import es.mityc.javasign.ssl.SimpleSSLManager;
//
///**
// * <p>Tests de de peticiones de sellos de tiempo a TSA vía http.</p>
// * <p>Requisitos:<ul>
// * 	<li>El fichero de propiedades debe estar en la raíz de los recursos con el nombre <code>testTSA.properties</code>. El fichero
// * deber incluir la propiedad:
// * <pre>
// * # Ruta donde se encuentra la TSA de pruebas SSL
// * test.tsa.ssl.url=
// * # Ruta del recurso que contiene la clave privada y certificado de identificación del cliente
// * test.tsa.ssl.cert=/keystores/usr0032.p12
// * # Contraseña de acceso al almacén
// * test.tsa.ssl.pass=usr0032
// * </pre></li></ul>
// * </p>
// * 
// * @author  Ministerio de Industria, Turismo y Comercio
// * @version 1.0
// */
//public class TestTSASSL {
//	
//	/** Ruta de la TSA de pruebas. */
//	private String urlTSA = "";
//	/** Ruta del fichero P12 que contiene el certificado de identificación del usuario. */
//	private String pathP12 = "";
//	/** Contraseña de acceso a la clave privada del usuario. */
//	private String passP12 = "";
//	
//	/**
//	 * <p>Recupera la configuración de acceso a la TSApara estas pruebas.</p>
//	 */
//	@Before 
//	public void initialize() {
//		try {
//			ResourceBundle rb = ResourceBundle.getBundle("testTSA");
//			urlTSA = rb.getString("test.tsa.ssl.url");
//			pathP12 = rb.getString("test.tsa.ssl.cert");
//			passP12 = rb.getString("test.tsa.ssl.pass");
//		} catch (MissingResourceException ex) {
//			fail("No se encuentra disponible la configuración específica para este test. Recuerde crear y configurar el fichero testTSA.properties");
//		}
//	}
//	
//	private void prepareSSL() {
//		KeyStore ks = null;
//		try {
//			ks = KeyStore.getInstance("PKCS12");
//			ks.load(this.getClass().getResourceAsStream(pathP12), passP12.toCharArray());
//			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
//			kmf.init(ks, passP12.toCharArray());
//			TSCliente.setSSLManager(new SimpleSSLManager(new AllTrustedManager(), kmf.getKeyManagers()[0]));
//		} catch (CertificateException ex) {
//			fail("Error al establecer la configuración de seguridad de la comunicación con la TSA: " + ex.getMessage());
//		} catch (KeyStoreException ex) {
//			fail("Error al establecer la configuración de seguridad de la comunicación con la TSA: " + ex.getMessage());
//		} catch (NoSuchAlgorithmException ex) {
//			fail("Error al establecer la configuración de seguridad de la comunicación con la TSA: " + ex.getMessage());
//		} catch (IOException ex) {
//			fail("Error al establecer la configuración de seguridad de la comunicación con la TSA: " + ex.getMessage());
//		} catch (UnrecoverableKeyException ex) {
//			fail("Error al establecer la configuración de seguridad de la comunicación con la TSA: " + ex.getMessage());
//		}
//	}
//	
//	@Test
//	public void testTSA() {
//		prepareSSL();
//		TSCliente client = new TSCliente(urlTSA, ConstantesTSA.SHA1);
//		byte result[] = null;
//		byte data[] = new byte[1024];
//		try {
//			result = client.generarSelloTiempo(data);
//		} catch (TSClienteError ex) {
//			fail("Error obteniendo sello de tiempo de " + urlTSA + ": " + ex.getMessage());
//		}
//		try {
//			TSValidator.validarSelloTiempo(data, result);
//		} catch (NoSuchAlgorithmException ex) {
//			fail("Error comprobando sello de tiempo obtenido: " + ex.getMessage());
//		} catch (NoSuchProviderException ex) {
//			fail("Error comprobando sello de tiempo obtenido: " + ex.getMessage());
//		} catch (CertStoreException ex) {
//			fail("Error comprobando sello de tiempo obtenido: " + ex.getMessage());
//		} catch (TSPException ex) {
//			fail("Error comprobando sello de tiempo obtenido: " + ex.getMessage());
//		} catch (IOException ex) {
//			fail("Error comprobando sello de tiempo obtenido: " + ex.getMessage());
//		} catch (TSClienteError ex) {
//			fail("Error comprobando sello de tiempo obtenido: " + ex.getMessage());
//		}
//	}
//
//
//}
