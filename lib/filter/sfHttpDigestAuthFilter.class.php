<?php
/*
 * This file is part of the Libcast sfHttpDigestAuth plugin.
 *
 * (c) 2011 Libcast SAS (www.libcast.com)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Try to authenticate a user via the HTTP Digest protocol
 *
 * @link      http://tools.ietf.org/html/rfc2617
 *
 * @package   sfHttpDigestAuthPlugin
 * @author    Keven Godet <keven@libcast.com>
 */
class sfHttpDigestAuthFilter extends sfFilter
{
  /**
   * @see sfFilter
   */
  public function execute($filterChain)
  {
    $digest = new HTTPDigest();
    $digest->nonceLife = $this->getParameter('nonce_life', 300);
    $digest->passwordsHashed = $this->getParameter('password_is_hash', true);
    $digest->privateKey = $this->getParameter('private_key', 'private_key');
    $digest->realm = $this->getParameter('realm', 'Realm');

    if ($this->isFirstCall() && !$this->context->getUser()->isAuthenticated())
    {
      $settings = array_merge(array(
          'retrieve' => array('sfGuardUserProvider', 'findForUser'),
          'signin' => array('sfGuardUserProvider', 'signIn'),
        ),
        sfConfig::get('app_sfHttpDigestAuth_callback', array()
      ));

      try
      {
        if ($username = $digest->authenticate($settings['retrieve']))
        {
          $this->context->getLogger()->notice(sprintf('User %s authenticated through HTTP Digest.', $username));
          call_user_func_array($settings['signin'], array($username));
          if (!$this->context->getUser()->isAuthenticated() && sfConfig::get('sf_logging_enabled'))
          {
            sfContext::getInstance()->getEventDispatcher()->notify(new sfEvent($this, 'application.log', array('User signin failed.', 'priority' => sfLogger::WARNING)));
          }
        }
      }
      catch(Exception $e)
      {
        if (sfConfig::get('sf_logging_enabled'))
        {
          sfContext::getInstance()->getEventDispatcher()->notify(new sfEvent($this, 'application.log', array($e->getMessage(), 'priority' => sfLogger::ERR)));
        }
      }

      if (!$this->context->getUser()->isAuthenticated())
      {
        $digest->send($this->getContext()->getRequest()->getParameter('scheme'));
        throw new sfStopException();
      }
    }

    $filterChain->execute();
  }
}