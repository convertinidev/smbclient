<?php

namespace ConvertiniDev;

use Icewind\SMB\AnonymousAuth;
use Icewind\SMB\BasicAuth;
use Icewind\SMB\Exception\InvalidTypeException;
use Icewind\SMB\Exception\NotFoundException;
use Icewind\SMB\IAuth;
use Icewind\SMB\IOptions;
use Icewind\SMB\IServer;
use Icewind\SMB\IShare;
use Icewind\SMB\KerberosAuth;
use Icewind\SMB\Options;
use Icewind\SMB\ServerFactory;

class SmbClient
{
    const AUTHBASIC = 'basic';
    const AUTHANON = 'anon';
    const AUTHKERBEROS = 'kerberos';
    public string $authProto; //AUTHBASIC (default), AUTHANON, AUTHKERBEROS (wip)

    public string $smbMinProtocol = IOptions::PROTOCOL_NT1;
    public string $smbMaxProtocol = IOptions::PROTOCOL_SMB3;

    public string $username;
    public string $password;
    public string $workgroup;
    public string $host;
    public string $share;

    protected IAuth $auth;
    protected IServer $server;

    /**
     * Se passati username e password viene settata l'auth basic altrimenti usa anon.
     * E' possibile cambiarlo successivamente.
     *
     * @param string|null $username
     * @param string|null $password
     * @param string|null $host
     * @param string $workgroup
     */
    public function __construct(?string $username = null, ?string $password = null, ?string $host = null, string $workgroup = 'WORKGROUP')
    {
        if (isset($host)) {
            $this->host = $host;
        }
        if (isset($username)) {
            $this->username = $username;
        }
        if (isset($password)) {
            $this->password = $password;
        }

        // auto-set auth
        if (isset($username) && isset($password)) {
            $this->authProto = self::AUTHBASIC;
        } else {
            $this->authProto = self::AUTHANON;
        }

        $this->workgroup = $workgroup;
    }

    /**
     * @return bool
     */
    public function checkConnector(): bool
    {
        if ( ! extension_loaded('smbclient')) {
            throw new Exception('Extension smbclient not loaded.');
        }

//        echo 'smbclient: '.smbclient_version().' on '.smbclient_library_version();
        return true;
    }

    /**
     * WIP
     * @todo estendere la libreria icewind1991/SMB
     */
    public function checkCredential(): bool
    {
        $this->checkConnector();

        $smb = $this->connect();
        if ($smb === null) {
            return false;
        }

        return true;
    }

    /**
     * Ritorna l'oggetto di connessione IServer
     *
     * @return IServer|null
     * @throws \Icewind\SMB\Exception\DependencyException
     */
    public function connect(): ?IServer
    {
        if (!isset($this->host) || !isset($this->username) || !isset($this->password) || !isset($this->workgroup)) {
            throw new Exception('Parametri mancanti in configurazione Samba');
        }

        $options = new Options();
        $options->setMinProtocol($this->smbMinProtocol);
        $options->setMaxProtocol($this->smbMaxProtocol);
        $options->setTimeout(10);

        $serverFactory = new ServerFactory($options);

        switch ($this->authProto) {
            case self::AUTHBASIC:
                $auth = new BasicAuth($this->username, $this->workgroup, $this->password);
                break;
            case self::AUTHKERBEROS:
                $auth = new KerberosAuth(); // @todo implementare KerberosAuth
                break;
            default:
                // self::AUTHANON
                $auth = new AnonymousAuth();
        }
        $this->auth = $auth;

        return $serverFactory->createServer($this->host, $auth);
    }

    /**
     * Restituisce l'ultimo file della cartella ordinando PER NOME
     *
     * @param IShare $share
     * @param string $dir
     * @return string
     */
    public static function getLastFileName(IShare $share, string $dir, string $extension = ''): string
    {
        try {
            $data = $share->dir(trim($dir, '/'));
        } catch (InvalidTypeException|NotFoundException $e) {
            echo 'Cartella SMB vuota: ' . $e->getMessage();
            return '';
        }

        $array = [];
        foreach ($data as $k=>$v) {
            $array[] = $v->getName();
        }
        krsort($array);

        $filename = '';
        foreach ( $array as $k=>$v) {
            if ($extension != '' && strtolower(pathinfo($v, PATHINFO_EXTENSION)) != $extension) {
                array_shift($array);
            } else {
                $filename = $array[$k];
                break;
            }
        }

        if (empty($array)) {
            echo 'Nessun file con estensione '.$extension;
            return '';
        }

        return $filename;
    }
}