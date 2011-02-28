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
 * Provides user passwords to the HTTPDigest class and sign user in when
 * authenticated with sfGuardUser and sfDoctrineGuardUser
 *
 * @package   sfHttpDigestAuthPlugin
 * @author    Keven Godet <keven@libcast.com>
 */
class sfGuardUserProvider
{
  /**
   *
   * @param string $username User to retrieve
   * @param Criteria $criteria Propel criteria
   *
   * @return string Password of the user
   */
  public static function findByUsername($username)
  {
    $user = self::retrievesfGuardUser($username);

    $settings = array_merge(array(
      'password_method'   => 'getPassword',
      'method_is_profile' => false,
    ),
    sfConfig::get('app_sfHttpDigestAuth_sfGuardUser', array()));
    if ($settings['method_is_profile'])
    {
      $user = $user->getProfile();
    }

    return $user->{$settings['password_method']}();
  }

  /**
   * Try to signin the freshly authenticated user
   *
   * @param string $username
   * @param sfGuardSecurityUser $username
   */
  public static function signIn($username, sfGuardSecurityUser $user = null)
  {
    if (is_null($user))
    {
      if (!sfContext::hasInstance())
      {
        throw new Exception('Signin process needs a user.');
      }

      $user = sfContext::getInstance()->getUser();
    }

    if (!$user instanceof sfGuardSecurityUser)
    {
      throw new Exception('Signin process needs a valid sfGuardSecurityUser instance.');
    }

    return $user->signIn(self::retrievesfGuardUser($username));
  }

  /**
   *
   * @param string $username
   *
   * @return sfGuardUser
   */
  public static function retrievesfGuardUser($username)
  {
    switch (self::orm())
    {
      case 'propel':
        return sfGuardUserPeer::retrieveByUsername($username, true);
        break;
      case 'doctrine':
        return sfGuardUserTable::retrieveByUsername($username, true);
        break;
      default:
        throw new Exception('The ORM is unknown.');
    }
  }

  /**
   * Guess the ORM
   *
   * @return string
   */
  public static function orm()
  {
    if (sfConfig::get('sf_orm'))
    {
      return sfConfig::get('sf_orm');
    }

    $tmp = new sfGuardUser();
    if ($tmp instanceof Doctrine_Record)
    {
      return 'doctrine';
    }

    if ($tmp instanceof BaseObject)
    {
      return 'propel';
    }

    return null;
  }
}