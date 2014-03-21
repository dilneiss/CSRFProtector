<?php 
class CSRFProtector {
	
	private $chaveAcesso;
	private $nomeToken;
	private $valorToken;
	private $horarioGerado;
	
	/**
	 * Inicia a validação via csrf
	 * Para chamar a validação apenas, necessário construir o objeto apenas com a chave de acesso 
	 * @param string $chaveAcesso Enviar uma chave de acesso para definir qual formulário está sendo gerado
	 */
	public function __construct($chaveAcesso){
		$this->setChaveAcesso($chaveAcesso);
		$this->setHorarioGerado(time());
	}
	
	/**
	 * Armazena na sessão o token inteiro
	 */
	private function storeInSession() {
		$_SESSION['csrf'][$this->getChaveAcesso()][$this->getNomeToken()] = serialize($this);
	}

	/**
	 *	Retira o token atual da sessão 
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
	 * Verifica se o token está expirado ou não
	 * TEMPO PRÉ DEFINIDO = 1800 segundos (30 minutos)
	 */
	private function isTokenExpirado(CSRFProtector $csrf){
		//SE O HORÁRIO DO SERVIDOR MENOS O HORÁRIO GERADO CONTINUA MENOR QUE O TEMPO DEFINIDO
		if ($_SERVER['REQUEST_TIME'] - $csrf->getHorarioGerado() < 1800){
			return false;
		}
		return true;
	}
	
	/**
	 * 	Gera um nome único
	 * 	@return CSRFProtector $csrf
	 */
	private function generateRandomName(){
		$this->setNomeToken(hash_hmac('sha256', openssl_random_pseudo_bytes(32), base64_encode( openssl_random_pseudo_bytes(32))));
	}
	
	/**
	 *	GERA UMA CHAVE NOVA CHAVE ENCRIPTOGRAFADA COM BASE NOS DADOS DO USUÁRIO ONDE PERMITIRÁ ACESSO 
	 *	A nova chave será gerada com base na chave de acesso ao formulário + navegador do usuário + ip do usuário
	 *	Essa chave será gerada uma nova MD5, que será encriptografada por rc4crypt e base64
	 *	@return CSRFProtector $csrf
	 */
	private function generateNewAccessKey(){
		$navegador = $_SERVER['HTTP_USER_AGENT'] ? $_SERVER['HTTP_USER_AGENT'] : 'semnavegador';
		$this->setChaveAcesso(base64_encode(md5('rdhdh465rd4h56rds4h56dr'.md5($navegador.getenv('REMOTE_ADDR').$this->getChaveAcesso()).'gsegse4ges489ges498gse984g98es49j8rt4jt')));
	}
	
	/**
	 *	Gera um token com base no nome aleatório, de formas encriptografadas diferentes
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
	 * Valida os formulários no início de toda requisição, se está postando, é obrigatóriamente ter enviado a proteção de csrf
	 * Se estiver em desenvolvimento, vai dar um alerta na tela
	 * Se estiver em produção, vai enviar um email e redirecionar para o erro inesperado
	 */
	public function validPagePostStart(){
		if (isset($_POST) && $_POST && count($_POST) && !isset($_POST['CSRFName']) && !isset($_POST['CSRFToken'])){
			$msg = "Formulário sem validação CSRF";
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
			//VALIDANDO SE A CHAVE NÃO ESTÁ EXPIRADA
			//VALIDANDO SE O VALOR DO TOKEN É O QUE ESTÁ SALVO NA SESSÃO
			if ($csrf && is_object($csrf) && !$this->isTokenExpirado($csrf) && $this->getValorToken() == $csrf->getValorToken()){
				$this->unsetSession();
				return true;
			}
			
		}
		
		return false;
		
	}
	
	
	/**
	 *	Gera os campos input hidden
	 *	var $pageName (Enviar caso for necessário definir um nome único para os nomes dos inputs)
	 *	var $id (Enviar em caso específico de precisar utilizar por id, exeplo de uso em ajax que só tem em uma página
	 */
	public function gerarHiddenInput($pageName=null, $id=false){
		
		//SE NÃO TEM UM TOKEN GERADO AINDA PARA OS INPUTS, VAI GERAR
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
		//SE NÃO TEM UM TOKEN GERADO AINDA PARA OS INPUTS, VAI GERAR
		if (!$this->getNomeToken() || !$this->getValorToken()){
			$this->gerarTokenSeguranca();
		}
		return " csrfname='{$this->getNomeToken()}' csrftoken='{$this->getValorToken()}'";
	}
	
	/**
	 * Gera a chave única, nome e token e armazena na sessão
	 */
	public function gerarTokenSeguranca(){
		
		$this->generateNewAccessKey(); 	//GERANDO A CHAVE DE ACESSO ÚNICA
		$this->generateRandomName();	//GERANDO O NOME ÚNICO PARA A CHAVE DE ACESSO
		$this->generateToken();			//GERANDO O VALOR ÚNICO PARA O NOME ÚNICO DA CHAVE ÚNICA
		
		//SALVANDO O CSRF na sessão
		$this->storeInSession();
		
	}
	
	public function gerarMensagemErro(){
		return "Ocorreu um erro inesperado com a sua solicitação<br />Caso o erro persista, por favor, entre em contato";
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