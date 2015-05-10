<?php
/**
 * php5rp_ng - PHP5 Reverse Proxy Next Generation
 *
 * @link      https://github.com/chricke/php5rp_ng
 * @copyright Copyright (c) 2010, 2013 Christian "chricke" Beckmann < mail@christian-beckmann.net >.
 * @license   https://github.com/chricke/php5rp_ng/blob/master/README.md BSD license.
 */

class ProxyHandler
{
	/**
	 * Статусы ответов.
	 *
	 * @link http://httpstatus.es/
	 * @link http://upload.wikimedia.org/wikipedia/commons/6/65/Http-headers-status.gif?uselang=ru
	 *
	 * @var array
	 */
	private $_status_codes = array (
		100 => 'Continue',
		101 => 'Switching Protocols',
		102 => 'Processing', // (WebDAV) (RFC 2518)
		103 => 'Checkpoint',
		122 => 'Request-URI too long',
		200 => 'OK',
		201 => 'Created',
		202 => 'Accepted',
		203 => 'Non-Authoritative Information', // (since HTTP/1.1)
		204 => 'No Content',
		205 => 'Reset Content',
		206 => 'Partial Content',
		207 => 'Multi-Status', // (WebDAV) (RFC 4918)
		208 => 'Already Reported', // (WebDAV) (RFC 5842)
		226 => 'IM Used', // (RFC 3229)
		300 => 'Multiple Choices',
		301 => 'Moved Permanently',
		302 => 'Found',
		303 => 'See Other',
		304 => 'Not Modified',
		305 => 'Use Proxy', // (since HTTP/1.1)
		306 => 'Switch Proxy',
		307 => 'Temporary Redirect', // (since HTTP/1.1)
		308 => 'Resume Incomplete',
		400 => 'Bad Request',
		401 => 'Unauthorized',
		402 => 'Payment Required',
		403 => 'Forbidden',
		404 => 'Not Found',
		405 => 'Method Not Allowed',
		406 => 'Not Acceptable',
		407 => 'Proxy Authentication Required',
		408 => 'Request Timeout',
		409 => 'Conflict',
		410 => 'Gone',
		411 => 'Length Required',
		412 => 'Precondition Failed',
		413 => 'Request Entity Too Large',
		414 => 'Request-URI Too Long',
		415 => 'Unsupported Media Type',
		416 => 'Requested Range Not Satisfiable',
		417 => 'Expectation Failed',
		418 => 'I\'m a teapot', // (RFC 2324)
		420 => 'Enhance Your Calm',
		422 => 'Unprocessable Entity', // (WebDAV) (RFC 4918)
		423 => 'Locked', // (WebDAV) (RFC 4918)
		424 => 'Failed Dependency', // (WebDAV) (RFC 4918)
		426 => 'Upgrade Required', // (RFC 2817)
		428 => 'Precondition Required',
		429 => 'Too Many Requests',
		431 => 'Request Header Fields Too Large',
		444 => 'No Response',
		449 => 'Retry With',
		450 => 'Blocked by Windows Parental Controls',
		451 => 'Wrong Exchange server',
		499 => 'Client Closed Request',
		500 => 'Internal Server Error',
		501 => 'Not Implemented',
		502 => 'Bad Gateway',
		503 => 'Service Unavailable',
		504 => 'Gateway Timeout',
		505 => 'HTTP Version Not Supported',
		506 => 'Variant Also Negotiates', // (RFC 2295)
		507 => 'Insufficient Storage', // (WebDAV) (RFC 4918)
		508 => 'Loop Detected', // (WebDAV) (RFC 5842)
		509 => 'Bandwidth Limit Exceeded', // (Apache bw/limited extension)
		510 => 'Not Extended', // (RFC 2774)
		511 => 'Network Authentication Required',
		598 => 'Network read timeout error',
		599 => 'Network connect timeout error',
	);

	/**
     * @type string
     */
    const RN = "\r\n";

    /**
     * @type boolean
     */
    private $_cacheControl = false;
    /**
     * @type boolean
     */
    private $_chunked = false;
    /**
     * @type array
     */
    private $_clientHeaders = array();
    /**
     * @type resource
     */
    private $_curlHandle;
    /**
     * @type boolean
     */
    private $_pragma = false;

	/**
	 * Body when chunked response
	 * @var string
	 */
	private $_body = '';

	/**
	 * @var string
	 */
	private $_encoding = '';

	/**
	 * @var bool
	 */
	private $_passRealIP = true;

	/**
	 * Uri
	 * @var string
	 */
	private $_translatedUri = '';

	/**
	 * http status of response
	 * @var int
	 */
	private $_httpStatus = 0;

	/**
	 * User specified callback to modify client headers
	 * Called for each header (two arguments: headerName, value)
	 * Should return array of two elements 0=>headerName, 1=>value
	 * Or false if header should be removed from request to upstream
	 *
	 * @var null|callback
	 */
	private $_processClientHeaderCallback = null;

	/**
	 * User specified callback to filter response headers
	 * Called for each header
	 * Should return modified header or empty string to skip header
	 * @var null|callback
	 */
	private $_filterResponseHeaderCallback = null;

	/**
	 * User specified callback to filter response body
	 * Called for body
	 * Should return modified body
	 * @var null|callback
	 */
	private $_filterResponseBodyCallback = null;

    /**
     * Create a new ProxyHandler
     *
     * @param array|string $options
     */
    function __construct($options)
    {
        if (is_string($options)) {
            $options = array('proxyUri' => $options);
        }
        // Trim slashes, we will append what is needed later
        $translatedUri = rtrim($options['proxyUri'], '/');

        // Get all parameters from options

        $baseUri = '';
        if (isset($options['baseUri'])) {
            $baseUri = $options['baseUri'];
        }
        elseif (!empty($_SERVER['REDIRECT_URL'])) {
            $baseUri = dirname($_SERVER['REDIRECT_URL']);
        }

        $requestUri = '';
        if (isset($options['requestUri'])) {
            $requestUri = $options['requestUri'];
        }
        else {
            if (!empty($_SERVER['REQUEST_URI'])) {
                $requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
            }
            if (!empty($_SERVER['QUERY_STRING'])) {
                $requestUri .= '?' . $_SERVER['QUERY_STRING'];
            }
        }

        if (!empty($requestUri)) {
            if (!empty($baseUri)) {
                $baseUriLength = strlen($baseUri);
                if (substr($requestUri, 0, $baseUriLength) === $baseUri) {
                    $requestUri = substr($requestUri, $baseUriLength);
                }
            }
            $translatedUri .= $requestUri;
        }
        else {
            $translatedUri .= '/';
        }

		if ( isset($options['processClientHeaderCallback']) ) {
			$this->_processClientHeaderCallback = $options['processClientHeaderCallback'];
		}
		if ( isset($options['filterResponseHeaderCallback']) ) {
			$this->_filterResponseHeaderCallback = $options['filterResponseHeaderCallback'];
		}
		if ( isset($options['filterResponseBodyCallback']) ) {
			$this->_filterResponseBodyCallback = $options['filterResponseBodyCallback'];
		}

		if ( isset($options['passRealIP']) ) {
			$this->_passRealIP = (bool) $options['passRealIP'];
		}

		$this->_translatedUri = $translatedUri;

        $this->_curlHandle = curl_init($this->_translatedUri);

        // Set various cURL options
        $this->setCurlOption(CURLOPT_FOLLOWLOCATION, true);
        $this->setCurlOption(CURLOPT_RETURNTRANSFER, true);
        // For images, etc.
        $this->setCurlOption(CURLOPT_BINARYTRANSFER, true);
		$this->setCurlOption(CURLOPT_WRITEFUNCTION, array($this, 'readResponse'));
		$this->setCurlOption(CURLOPT_HEADERFUNCTION, array($this, 'readHeaders'));
		//$this->setCurlOption(CURLOPT_VERBOSE, true);

        $requestMethod = '';
        if (isset($options['requestMethod'])) {
            $requestMethod = $options['requestMethod'];
        }
        elseif (!empty($_SERVER['REQUEST_METHOD'])) {
            $requestMethod = $_SERVER['REQUEST_METHOD'];
        }

        // Default cURL request method is 'GET'
        if ($requestMethod !== 'GET') {
            $this->setCurlOption(CURLOPT_CUSTOMREQUEST, $requestMethod);

            $inputStream = isset($options['inputStream']) ? $options['inputStream'] : 'php://input';

            switch($requestMethod) {
                case 'POST':
                    if (isset($options['data'])) {
                        $data = $options['data'];
                    }
                    else {
                        if (!isset($HTTP_RAW_POST_DATA)) {
                            $HTTP_RAW_POST_DATA = file_get_contents($inputStream);
                        }
                        $data = $HTTP_RAW_POST_DATA;
                    }
                    $this->setCurlOption(CURLOPT_POSTFIELDS, $data);
                    break;
                    
                case 'PUT':
                    // Set the request method.
                    $this->setCurlOption(CURLOPT_UPLOAD, 1);
                    // PUT data comes in on the stdin stream.
                    $putData = fopen($inputStream, 'r');
                    $this->setCurlOption(CURLOPT_READDATA, $putData);
                    // TODO: set CURLOPT_INFILESIZE to the value of Content-Length.
                    break;
            }
        }

        // Handle the client headers.
        $this->handleClientHeaders();
    }

    /**
     * @return array
     */
    private function _getRequestHeaders()
    {
        if (function_exists('apache_request_headers')) {
            if ($headers = apache_request_headers()) {
                return $headers;
            }
        }

        $headers = array();
        foreach ($_SERVER as $key => $value) {
            if (substr($key, 0, 5) == 'HTTP_' && !empty($value)) {
                $headerName = strtolower(substr($key, 5, strlen($key)));
                $headerName = str_replace(' ', '-', ucwords(str_replace('_', ' ', $headerName)));
                $headers[$headerName] = $value;
            }
        }
        return $headers;
    }

    /**
     * @param string $headerName
     * @return void
     */
    private function _removeHeader($headerName)
    {
        if (function_exists('header_remove')) {
            header_remove($headerName);
        } else {
            header($headerName . ': ');
        }
    }

    /**
     * Adds the remote servers address to the 'X-Forwarded-For' headers,
     * sets the 'X-Real-IP' header to the first address forwarded to and
     * removes some headers we shouldn't pass through.
     *
     * @return void
     */
    protected function handleClientHeaders()
    {
        $headers = $this->_getRequestHeaders();
        $xForwardedFor = array();

        foreach ($headers as $headerName => $value) {
			$l = $this->processClientHeader($headerName, $value);
			if ( $l !== false ) {
				$this->setClientHeader($l[0], $l[1]);
				continue;
			}
			switch($headerName) {
                case 'Host':
                case 'X-Real-IP':
                    break;

                case 'X-Forwarded-For':
                    $xForwardedFor[] = $value;
                    break;

                default:
                    $this->setClientHeader($headerName, $value);
                    break;
            }
        }

        if ( $this->_passRealIP === true ) {
			$xForwardedFor[] = $_SERVER['REMOTE_ADDR'];
			$this->setClientHeader('X-Forwarded-For', implode(',', $xForwardedFor));
			$this->setClientHeader('X-Real-IP', $xForwardedFor[0]);
		}
    }

	/**
	 * Process client header (call user callback)
	 * Header can be modified by user func or deny to proxy pass
	 *
	 * @param $headerName
	 * @param $value
	 * @return array|bool - array if header should be set, false otherwise
	 */
	protected function processClientHeader($headerName, $value)
	{
		if ( $this->_processClientHeaderCallback !== null ) {
			$l = call_user_func( $this->_processClientHeaderCallback, $headerName, $value );
			if ( $l !== false && is_array($l) && count($l) === 2)
				return $l;
			else
				return false;
		}
		else
			return array ( $headerName, $value );
	}

    /**
     * Our handler for cURL option CURLOPT_HEADERFUNCTION
     *
     * @param resource $cu
     * @param string $header
     * @return int
     */
    protected function readHeaders(&$cu, $header)
    {
        $length = strlen($header);

		if (preg_match(',^HTTP/[^\s]+\s+(\d+)\s+,', $header, $rg)) {
            $this->_httpStatus = intval($rg[1]);
			if ( $this->_httpStatus === 0 || !in_array($this->_httpStatus, $this->_status_codes) )
				$this->_httpStatus = 500;
            // skip this header
			return $length;
        }
		elseif (preg_match(',^Cache-Control:,', $header)) {
            $this->_cacheControl = true;
        }
        elseif (preg_match(',^Pragma:,', $header)) {
            $this->_pragma = true;
        }
        elseif (preg_match(',^Transfer-Encoding:,', $header)) {
            $this->_chunked = strpos($header, 'chunked') !== false;
			// skip this header
			return $length;
        }
		elseif (preg_match(',^Content-Encoding:(.+)$,', trim($header), $rg)) {
			$this->_encoding = trim($rg[1]);
			// skip this header
			return $length;
		}


        if ($header !== self::RN) {
            if ( $this->_filterResponseHeaderCallback !== null ) {
				$header = call_user_func( $this->_filterResponseHeaderCallback, $header );
				if ( $header !== "" ) {
					header($header, false);
				}
			} else {
				header(rtrim($header), false);
			}
        }

        return $length;
    }

    /**
     * Our handler for cURL option CURLOPT_WRITEFUNCTION
     *
     * @param resource $cu
     * @param string $body
     * @return int
     */
    protected function readResponse(&$cu, $body)
    {
        static $headersParsed = false;

        // Clear the Cache-Control and Pragma headers
        // if they aren't passed from the proxy application.
        if ($headersParsed === false) {
            if (!$this->_cacheControl) {
                $this->_removeHeader('Cache-Control');
            }
            if (!$this->_pragma) {
                $this->_removeHeader('Pragma');
            }
            $headersParsed = true;
        }

		$length = strlen($body);

		$this->_body .= $body;

        return $length;
    }

    /**
     * Close the cURL handle and a possible chunked response
     *
     * @return void
     */
    public function close()
    {
		header(isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0', ' ' . $this->_httpStatus . ' ' . $this->_status_codes[$this->_httpStatus], true);

		if ( $this->_encoding == 'gzip' ) {
			$this->_body = gzdecode($this->_body);
		}
		if ($this->_chunked) {
			if ( $this->_filterResponseBodyCallback !== null ) {
				echo call_user_func( $this->_filterResponseBodyCallback, $this->_translatedUri, $this->_body );
			} else {
				echo $this->_body;
			}
		}else{
			echo $this->_body;
		}

        curl_close($this->_curlHandle);
    }

    /**
     * Executes the cURL handler, making the proxy request.
     * Returns true if request is successful, false if there was an error.
     * By checking this return, you may output the return from getCurlError
     * Or output your own bad gateway page.
     *
     * @return boolean
     */
    public function execute()
    {
        $this->setCurlOption(CURLOPT_HTTPHEADER, $this->_clientHeaders);
        return curl_exec($this->_curlHandle) !== false;
    }

    /**
     * Get possible cURL error.
     * Should NOT be called before exec.
     *
     * @return string
     */
    public function getCurlError()
    {
        return curl_error($this->_curlHandle);
    }

    /**
     * Get information about the request.
     * Should NOT be called before exec.
     *
     * @return array
     */
    public function getCurlInfo()
    {
        return curl_getinfo($this->_curlHandle);
    }

    /**
     * Sets a new header that will be sent with the proxy request
     *
     * @param string $headerName
     * @param string $value
     * @return void
     */
    public function setClientHeader($headerName, $value)
    {
        $this->_clientHeaders[] = $headerName . ': ' . $value;
    }

    /**
     * Sets a cURL option.
     *
     * @param string $option
     * @param string $value
     * @return void
     */
    public function setCurlOption($option, $value)
    {
        curl_setopt($this->_curlHandle, $option, $value);
    }
}


if ( !function_exists('gzdecode') ) {
	include 'func.gzdecode.php';
}
