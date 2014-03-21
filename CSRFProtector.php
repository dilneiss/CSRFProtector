<?php 
class CSRFProtector {
	
	private $chaveAcesso;
	private $nomeToken;
	private $valorToken;
	private $horarioGerado;
	
	/**
	 * Inicia a valida��o via csrf
	 * Para chamar a valida��o apenas, necess�rio construir o objeto apenas com a chave de acesso 
	 * @param string $chaveAcesso Enviar uma chave de acesso para definir qual formul�rio est� sendo gerado
	 */
	public function __construct($chaveAcesso){
		$this->setChaveAcesso($chaveAcesso);
		$this->setHorarioGerado(time());
	}
	
	/**
	 * Armazena na sess�o o token inteiro
	 */
	private function storeInSession() {
		$_SESSION['csrf'][$this->getChaveAcesso()][$this->getNomeToken()] = serialize($this);
	}

	/**
	 *	Retira o token atual da sess�o 
	 */
	private function unsetSession() {
		unset($_SESSION['csrf'][$this->getChaveAcesso()][$this->getNomeToken()]);
	}
	
	/**
	 *	Retorna o objeto inteiro se tiver
	 *	@return CSRFProtector $csrf
	 */
	private function getFromSession() {
		if (isset($_SESSION['csrf'][$this->getChaveAcesso()][$this->getNomeToken()])) {
			return unserialize($_SESSION['csrf'][$this->getChaveAcesso()][$this->getNomeToken()]);
		}
		return false; 
	}
	
	
	/**
	 * Verifica se o token est� expirado ou n�o
	 * TEMPO PR� DEFINIDO = 1800 segundos (30 minutos)
	 */
	private function isTokenExpirado(CSRFProtector $csrf){
		//SE O HOR�RIO DO SERVIDOR MENOS O HOR�RIO GERADO CONTINUA MENOR QUE O TEMPO DEFINIDO
		if ($_SERVER['REQUEST_TIME'] - $csrf->getHorarioGerado() < 1800){
			return false;
		}
		return true;
	}
	
	/**
	 * 	Gera um nome �nico
	 * 	@return CSRFProtector $csrf
	 */
	private function generateRandomName(){
		$this->setNomeToken(hash_hmac('sha256', openssl_random_pseudo_bytes(32), base64_encode( openssl_random_pseudo_bytes(32))));
	}
	
	/**
	 *	GERA UMA CHAVE NOVA CHAVE ENCRIPTOGRAFADA COM BASE NOS DADOS DO USU�RIO ONDE PERMITIR� ACESSO 
	 *	A nova chave ser� gerada com base na chave de acesso ao formul�rio + navegador do usu�rio + ip do usu�rio
	 *	Essa chave ser� gerada uma nova MD5, que ser� encriptografada por rc4crypt e base64
	 *	@return CSRFProtector $csrf
	 */
	private function generateNewAccessKey(){
		$navegador = $_SERVER['HTTP_USER_AGENT'] ? $_SERVER['HTTP_USER_AGENT'] : 'semnavegador';
		$this->setChaveAcesso(base64_encode(md5('rdhdh465rd4h56rds4h56dr'.md5($navegador.getenv('REMOTE_ADDR').$this->getChaveAcesso()).'gsegse4ges489ges498gse984g98es49j8rt4jt')));
	}
	
	/**
	 *	Gera um token com base no nome aleat�rio, de formas encriptografadas diferentes
	 *	@return CSRFProtector $csrf
	 */
	private function generateToken() {
		if (function_exists("hash_algos") && in_array("sha512",hash_algos())) {
			$token = hash("sha512",mt_rand(0,mt_getrandmax()));
		} else {
			$token=' ';
			for ($i=0;$i<128;++$i) {
				$r=mt_rand(0,35);
				if ($r<26) {
					$c=chr(ord('a')+$r);
				} else {
					$c=chr(ord('0')+$r-26);
				} 
				$token.=$c;
			}
		}
		$this->setValorToken($token);
	}
	
	/**
	 * Valida os formul�rios no in�cio de toda requisi��o, se est� postando, � obrigat�riamente ter enviado a prote��o de csrf
	 * Se estiver em desenvolvimento, vai dar um alerta na tela
	 * Se estiver em produ��o, vai enviar um email e redirecionar para o erro inesperado
	 */
	public function validPagePostStart(){
		if (isset($_POST) && $_POST && count($_POST) && !isset($_POST['CSRFName']) && !isset($_POST['CSRFToken'])){
			$msg = "Formul�rio sem valida��o CSRF";
			if (SERVER_MODE_DEVELOPER){
				exit($msg);
			}else{
				enviaEmailError($msg);
				redirect(URL.PageURL::ERRO_INESPERADO);
			}
		}
	}
	
	/**
	 * VALIDA O TOKEN POSTADO 
	 */
	public function validateToken() {

		//VALIDANDO SE POSTOU O TOKEN E TEM ALGO NO TOKEN
		if (mb_strtolower($_SERVER['REQUEST_METHOD']) == 'post' && isset($_POST['CSRFName']) && $_POST['CSRFName'] && isset($_POST['CSRFToken']) && $_POST['CSRFToken']){
			
			$this->generateNewAccessKey();
			$this->setNomeToken($_POST['CSRFName']);
			$this->setValorToken($_POST['CSRFToken']);
			
			$csrf = $this->getFromSession();

			//VALIDANDO SE TEM UMA CHAVE PARA ELE
			//VALIDANDO SE A CHAVE N�O EST� EXPIRADA
			//VALIDANDO SE O VALOR DO TOKEN � O QUE EST� SALVO NA SESS�O
			if ($csrf && is_object($csrf) && !$this->isTokenExpirado($csrf) && $this->getValorToken() == $csrf->getValorToken()){
				$this->unsetSession();
				return true;
			}
			
		}
		
		return false;
		
	}
	
	
	/**
	 *	Gera os campos input hidden
	 *	var $pageName (Enviar caso for necess�rio definir um nome �nico para os nomes dos inputs)
	 *	var $id (Enviar em caso espec�fico de precisar utilizar por id, exeplo de uso em ajax que s� tem em uma p�gina
	 */
	public function gerarHiddenInput($pageName=null, $id=false){
		
		//SE N�O TEM UM TOKEN GERADO AINDA PARA OS INPUTS, VAI GERAR
		if (!$this->getNomeToken() || !$this->getValorToken()){
			$this->gerarTokenSeguranca();
		}
		
		$idName = '';
		$idToken = '';
		if ($id){
			$idName = "id='csrfname$pageName'";
			$idToken = "id='csrftoken$pageName'";
		}
		
		//GERANDO OS INPUTS PRONTOS
		return "<input class='csrfname$pageName' type='hidden' $idName name='CSRFName' value='{$this->getNomeToken()}' />
				<input class='csrftoken$pageName' type='hidden' $idToken name='CSRFToken' value='{$this->getValorToken()}' />";
		
	}
	
	/**
	 * Gera as tags em html para uso em ajax
	 */
	public function gerarHtmlTagsAjax(){
		//SE N�O TEM UM TOKEN GERADO AINDA PARA OS INPUTS, VAI GERAR
		if (!$this->getNomeToken() || !$this->getValorToken()){
			$this->gerarTokenSeguranca();
		}
		return " csrfname='{$this->getNomeToken()}' csrftoken='{$this->getValorToken()}'";
	}
	
	/**
	 * Gera a chave �nica, nome e token e armazena na sess�o
	 */
	public function gerarTokenSeguranca(){
		
		$this->generateNewAccessKey(); 	//GERANDO A CHAVE DE ACESSO �NICA
		$this->generateRandomName();	//GERANDO O NOME �NICO PARA A CHAVE DE ACESSO
		$this->generateToken();			//GERANDO O VALOR �NICO PARA O NOME �NICO DA CHAVE �NICA
		
		//SALVANDO O CSRF na sess�o
		$this->storeInSession();
		
	}
	
	public function gerarMensagemErro(){
		return "Ocorreu um erro inesperado com a sua solicita��o<br />Caso o erro persista, por favor, entre em contato";
	}
	
	public function getChaveAcesso() {
	    return $this->chaveAcesso;
	}

	public function setChaveAcesso($chaveAcesso) {
	    $this->chaveAcesso = $chaveAcesso;
	}

	public function getNomeToken() {
	    return $this->nomeToken;
	}

	public function setNomeToken($nomeToken) {
	    $this->nomeToken = $nomeToken;
	}

	public function getValorToken() {
	    return $this->valorToken;
	}

	public function setValorToken($valorToken) {
	    $this->valorToken = $valorToken;
	}
	
	public function getHorarioGerado() {
	    return $this->horarioGerado;
	}

	public function setHorarioGerado($horarioGerado) {
	    $this->horarioGerado = $horarioGerado;
	}

}
?>