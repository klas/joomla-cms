<?php
/**
 * Joomla! Content Management System
 *
 * @copyright  Copyright (C) 2005 - 2017 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE.txt
 */

namespace Joomla\CMS\Access;

defined('JPATH_PLATFORM') or die;

use Joomla\CMS\Authorize\Authorize;
use Joomla\CMS\Authorize\AuthorizeHelper;

/**
 * Class that handles all access authorisation routines.
 *
 * @since       11.1
 * @deprecated  No replacement, to be removed in 4.2.
 */
class Access
{
	/**
	 * Array of view levels
	 *
	 * @var    array
	 * @since  11.1
	 */
	protected static $viewLevels = array();

	/**
	 * Method for clearing static caches.
	 *
	 * @return  void
	 *
	 * @since   11.3
	 */
	public static function clearStatics()
	{
		self::$viewLevels = array();

		$access = Authorize::getInstance('JoomlaLegacy');
		$access->clearStatics();
	}

	/**
	 * Method to return a list of view levels for which the user is authorised.
	 *
	 * @param   integer  $userId  Id of the user for which to get the list of authorised view levels.
	 *
	 * @return  array    List of view levels for which the user is authorised.
	 *
	 * @since   11.1
	 */
	public static function getAuthorisedViewLevels($userId)
	{
		// Get all groups that the user is mapped to recursively.
		$groups = \JUserHelper::getGroupsByUser($userId);

		// Only load the view levels once.
		if (empty(self::$viewLevels))
		{
			// Get a database object.
			$db = \JFactory::getDbo();

			// Build the base query.
			$query = $db->getQuery(true)
				->select('id, rules')
				->from($db->quoteName('#__viewlevels'));

			// Set the query for execution.
			$db->setQuery($query);

			// Build the view levels array.
			foreach ($db->loadAssocList() as $level)
			{
				self::$viewLevels[$level['id']] = (array) json_decode($level['rules']);
			}
		}

		// Initialise the authorised array.
		$authorised = array(1);

		// Check for the recovery mode setting and return early.
		$user      = \JUser::getInstance($userId);
		$root_user = \JFactory::getConfig()->get('root_user');

		if ($root_user && ($root_user == $user->username || $root_user == $user->id))
		{
			// Find the super user levels.
			foreach (self::$viewLevels as $level => $rule)
			{
				foreach ($rule as $id)
				{
					if ($id > 0 && self::checkGroup($id, 'core.admin'))
					{
						$authorised[] = $level;
						break;
					}
				}
			}

			return $authorised;
		}

		// Get all groups that the user is mapped to recursively.
		$groups = self::getGroupsByUser($userId);

		// Find the authorised levels.
		foreach (self::$viewLevels as $level => $rule)
		{
			foreach ($rule as $id)
			{
				if (($id < 0) && (($id * -1) == $userId))
				{
					$authorised[] = $level;
					break;
				}
				// Check to see if the group is mapped to the level.
				elseif (($id >= 0) && in_array($id, $groups))
				{
					$authorised[] = $level;
					break;
				}
			}
		}

		return $authorised;
	}

	/**
	 * Method to return a list of actions for which permissions can be set given a component and section.
	 *
	 * @param   string  $component  The component from which to retrieve the actions.
	 * @param   string  $section    The name of the section within the component from which to retrieve the actions.
	 *
	 * @return  array  List of actions available for the given component and section.
	 *
	 * @since       11.1
	 * @deprecated  12.3 (Platform) & 4.0 (CMS)  Use Access::getActionsFromFile or Access::getActionsFromData instead.
	 * @codeCoverageIgnore
	 */
	public static function getActions($component, $section = 'component')
	{
		\JLog::add(__METHOD__ . ' is deprecated. Use Access::getActionsFromFile or Access::getActionsFromData instead.', \JLog::WARNING, 'deprecated');

		$actions = self::getActionsFromFile(
			JPATH_ADMINISTRATOR . '/components/' . $component . '/access.xml',
			"/access/section[@name='" . $section . "']/"
		);

		if (empty($actions))
		{
			return array();
		}
		else
		{
			return $actions;
		}
	}

	/**
	 * Method to return a list of actions from a file for which permissions can be set.
	 *
	 * @param   string  $file   The path to the XML file.
	 * @param   string  $xpath  An optional xpath to search for the fields.
	 *
	 * @return  boolean|array   False if case of error or the list of actions available.
	 *
	 * @since   12.1
	 */
	public static function getActionsFromFile($file, $xpath = "/access/section[@name='component']/")
	{
		return AuthorizeHelper::getActionsFromFile($file, $xpath);
	}

	/**
	 * Method to return a list of actions from a string or from an xml for which permissions can be set.
	 *
	 * @param   string|\SimpleXMLElement  $data   The XML string or an XML element.
	 * @param   string                    $xpath  An optional xpath to search for the fields.
	 *
	 * @return  boolean|array   False if case of error or the list of actions available.
	 *
	 * @since   12.1
	 */
	public static function getActionsFromData($data, $xpath = "/access/section[@name='component']/")
	{
		return AuthorizeHelper::getActionsFromData($data, $xpath);
	}

	/**
	 * Method to get the extension name from the asset name.
	 *
	 * @param   string  $asset  Asset Name
	 *
	 * @return  string  Extension Name.
	 *
	 * @since    1.6
	 */
	public static function getExtensionNameFromAsset($asset)
	{
		return AuthorizeHelper::getExtensionNameFromAsset($asset);
	}

	/**
	 * Method to check if a user is authorised to perform an action, optionally on an asset.
	 *
	 * @param   integer  $userId  Id of the user for which to check authorisation.
	 * @param   string   $action  The name of the action to authorise.
	 * @param   mixed    $asset   Integer asset id or the name of the asset as a string.  Defaults to the global asset node.
	 *
	 * @return  mixed  True if authorised and assetId is numeric/named. An array of boolean values if assetId is array.
	 *
	 * @since   11.1
	 * @deprecated  Use JAuthorize->check() instead
	 */
	public static function check($userId, $action, $asset = 1)
	{
		$access = Authorize::getInstance('JoomlaLegacy');
		$access->assetId = $asset;

		return $access->check($userId, $asset, $action, 'user');
	}

	/**
	 * Method to preload the JAccessRules object for the given asset type.
	 *
	 * @param   integer|string|array  $assetTypes  The type or name of the asset (e.g. 'com_content.article', 'com_menus.menu.2').
	 *                                             Also accepts the asset id. An array of asset type or a special
	 *                                             'components' string to load all component assets.
	 * @param   boolean               $reload      Set to true to reload from database.
	 *
	 * @return  void
	 *
	 * @since   1.6
	 */
	public static function preload($assetTypes = 'components', $reload = false)
	{
		return;
	}

	/**
	 * Method to retrieve the Asset Rule strings for this particular
	 * Asset Type and stores them for later usage in getAssetRules().
	 * Stores 2 arrays: one where the list has the Asset ID as the key
	 * and a second one where the Asset Name is the key.
	 *
	 * @param   string   $assetType  The asset type, or the asset name, or the extension of the asset
	 *                               (e.g. 'com_content.article', 'com_menus.menu.2', 'com_contact').
	 * @param   boolean  $reload     Reload the preloaded assets.
	 *
	 * @return  void
	 *
	 * @since   1.6
	 */
	protected static function preloadPermissions($assetType, $reload = false)
	{
		return;
	}

	/**
	 * Method to preload the JAccessRules objects for all components.
	 *
	 * Note: This will only get the base permissions for the component.
	 * e.g. it will get 'com_content', but not 'com_content.article.1' or
	 * any more specific asset type rules.
	 *
	 * @return   void
	 *
	 * @since    1.6
	 */
	protected static function preloadComponents()
	{
		return;
	}


	/**
	 * Method to check if a group is authorised to perform an action, optionally on an asset.
	 *
	 * @param   integer  $groupId  The path to the group for which to check authorisation.
	 * @param   string   $action   The name of the action to authorise.
	 * @param   mixed    $asset    Integer asset id or the name of the asset as a string.  Defaults to the global asset node.
	 *
	 * @return  boolean  True if authorised.
	 *
	 * @since   11.1
	 * @deprecated  Use JAuthorize->check() instead
	 */
	public static function checkGroup($groupId, $action, $asset = 1)
	{
		$access = Authorize::getInstance('JoomlaLegacy');
		$access->assetId = $asset;

		return $access->check($groupId, $asset, $action, 'group');
	}

	/**
	 * Method to return the JAccessRules object for an asset.  The returned object can optionally hold
	 * only the rules explicitly set for the asset or the summation of all inherited rules from
	 * parent assets and explicit rules.
	 *
	 * @param   mixed    $asset                 Integer asset id or the name of the asset as a string.
	 * @param   boolean  $recursive             True to return the rules object with inherited rules.
	 * @param   boolean  $recursiveParentAsset  True to calculate the rule also based on inherited component/extension rules.
	 * @param   boolean  $preload               Unused
	 *
	 * @return  Rules   JAccessRules object for the asset.
	 *
	 * @since   11.1
	 * @deprecated  No replacement. To be removed in 4.1.
	 */
	public static function getAssetRules($asset, $recursive = false, $recursiveParentAsset = false, $preload = true)
	{
		$access = Authorize::getInstance('JoomlaLegacy');
		$access->assetId = $asset;

		return $access->getRules($recursive, null, null);
	}

	/**
	 * Method to return the title of a user group
	 *
	 * @param   integer  $groupId  Id of the group for which to get the title of.
	 *
	 * @return  string  The title of the group
	 *
	 * @since   3.5
	 * @deprecated  Use JUserHelper::getGroupTitle instead
	 */
	public static function getGroupTitle($groupId)
	{
		return \JUserHelper::getGroupTitle($groupId);
	}

	/**
	 * Method to return a list of user groups mapped to a user. The returned list can optionally hold
	 * only the groups explicitly mapped to the user or all groups both explicitly mapped and inherited
	 * by the user.
	 *
	 * @param   integer  $userId     Id of the user for which to get the list of groups.
	 * @param   boolean  $recursive  True to include inherited user groups.
	 *
	 * @return  array    List of user group ids to which the user is mapped.
	 *
	 * @since   11.1
	 * @deprecated  Use JUserHelper::getGroupsByUser instead
	 */
	public static function getGroupsByUser($userId, $recursive = true)
	{
		return \JUserHelper::getGroupsByUser($userId, $recursive);
	}

	/**
	 * Method to return a list of user Ids contained in a Group
	 *
	 * @param   integer  $groupId    The group Id
	 * @param   boolean  $recursive  Recursively include all child groups (optional)
	 *
	 * @return  array
	 *
	 * @since   11.1
	 * @deprecated  Use JUserHelper::getUsersByGroup instead
	 */
	public static function getUsersByGroup($groupId, $recursive = false)
	{
		return \JUserHelper::getUsersByGroup($groupId, $recursive);
	}

	/**
	 * Gets the parent groups that a leaf group belongs to in its branch back to the root of the tree
	 * (including the leaf group id).
	 *
	 * @param   mixed  $groupId  An integer or array of integers representing the identities to check.
	 *
	 * @return  mixed  True if allowed, false for an explicit deny, null for an implicit deny.
	 *
	 * @since   11.1
	 * @deprecated  Use JUserHelper::getGroupPath instead
	 */
	protected static function getGroupPath($groupId)
	{
		return \JUserHelper::getGroupPath($groupId);
	}
}
