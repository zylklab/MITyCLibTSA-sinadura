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
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA.
 * 
 */
package es.mityc.javasign.ts;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStoreException;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.bouncycastle.tsp.TSPException;
import org.junit.Before;
import org.junit.Test;

import es.mityc.firmaJava.ts.ConstantesTSA;
import es.mityc.firmaJava.ts.TSCliente;
import es.mityc.firmaJava.ts.TSClienteError;
import es.mityc.firmaJava.ts.TSValidator;

/**
 * <p>Tests de de peticiones de sellos de tiempo a TSA vía http.</p>
 * <p>Requisitos:<ul>
 * 	<li>El fichero de propiedades debe estar en la raíz de los recursos con el nombre <code>testTSA.properties</code>. El fichero
 * deber incluir la propiedad:
 * <pre>
 * # Ruta donde se encuentra la TSA que se utilizará para los tests
 * test.tsa.url=
 * </pre></li></ul>
 * </p>
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class TestTSA {
	
	/** Ruta de la TSA de pruebas. */
	private String urlTSA = "";
	
	/**
	 * <p>Recupera la configuración de acceso a la TSApara estas pruebas.</p>
	 */
	@Before 
	public void initialize() {
		try {
			ResourceBundle rb = ResourceBundle.getBundle("testTSA");
			urlTSA = rb.getString("test.tsa.url");
		} catch (MissingResourceException ex) {
			fail("No se encuentra disponible la configuración específica para este test. Recuerde crear y configurar el fichero testTSA.properties");
		}
	}
	
	@Test
	public void testTSA() {
		TSCliente client = new TSCliente(urlTSA, ConstantesTSA.SHA1);
		byte result[] = null;
		byte data[] = new byte[1024];
		try {
			result = client.generarSelloTiempo(data);
		} catch (TSClienteError ex) {
			fail("Error obteniendo sello de tiempo de " + urlTSA + ": " + ex.getMessage());
		}
		try {
			TSValidator.validarSelloTiempo(data, result);
		} catch (NoSuchAlgorithmException ex) {
			fail("Error comprobando sello de tiempo obtenido: " + ex.getMessage());
		} catch (NoSuchProviderException ex) {
			fail("Error comprobando sello de tiempo obtenido: " + ex.getMessage());
		} catch (CertStoreException ex) {
			fail("Error comprobando sello de tiempo obtenido: " + ex.getMessage());
		} catch (TSPException ex) {
			fail("Error comprobando sello de tiempo obtenido: " + ex.getMessage());
		} catch (IOException ex) {
			fail("Error comprobando sello de tiempo obtenido: " + ex.getMessage());
		} catch (TSClienteError ex) {
			fail("Error comprobando sello de tiempo obtenido: " + ex.getMessage());
		}
	}


}
