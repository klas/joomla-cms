<?php
/**
 * @package     Joomla.Platform
 * @subpackage  Access
 *
 * @copyright   Copyright (C) 2005 - 2015 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE
 */

defined('JPATH_PLATFORM') or die;

jimport('joomla.utilities.arrayhelper');

/**
 * Class that handles all access authorisation routines.
 *
 * @since  11.1
 */
class JAccess
{
	/**
	 * Array of view levels
	 *
	 * @var    array
	 * @since  11.1
	 */
	protected static $viewLevels = array();

	/**
	 * Array of rules for the asset
	 *
	 * @var    array
	 * @since  11.1
	 */
	protected static $assetRules = array();

	public static $permCache = array();

	public static $rootAsset = null;

	protected $assetId = 1;

	protected $rules = null;

	protected $db = null;

	/**
	 * Instantiate the access class
	 *
	 * @param   mixed         $assetId  Assets id, can be numeric or string
	 * @param   JAccessRules  $rules    Rules object
	 *
	 * @since  3.6
	 */

	public function __construct($assetId = 1, JAccessRules $rules = null)
	{
		$this->set('assetId', $assetId);
		$this->rules = $rules;
		$this->db = JFactory::getDbo();
	}

	/**
	 * Method to set a value Example: $access->set('items', $items);
	 *
	 * @param   string  $name   Name of the property
	 * @param   mixed   $value  Value to assign to the property
	 *
	 * @return  self
	 *
	 * @since   3.6
	 */
	public function set($name, $value)
	{
		switch ($name)
		{
			case 'assetId':
				if (is_numeric($value))
				{
					$this->assetId = (int) $value;
				}
				else
				{
					$this->assetId = (string) $value;
				}
				break;
			case 'rules':
				if ($value instanceof JAccessRules)
				{
					$this->rules = $value;
				}
		}

		return $this;
	}

	/**
	 * Method to get the value
	 *
	 * @param   string  $key           Key to search for in the data array
	 * @param   mixed   $defaultValue  Default value to return if the key is not set
	 *
	 * @return  mixed   Value | defaultValue if doesn't exist
	 *
	 * @since   3.6
	 */
	public function get($key, $defaultValue = null)
	{
		return isset($this->$key) ? $this->$key : $defaultValue;
	}

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
		self::$assetRules = array();
		self::$permCache = array();
		self::$rootAsset = null;

		// Legacy
		JUserHelper::clearStatics();
	}

	/**
	 * Method to check if a user is authorised to perform an action, optionally on an asset.
	 *
	 * @param   integer  $id      Id of the user/group for which to check authorisation.
	 * @param   string   $action  The name of the action to authorise.
	 * @param   mixed    $asset   Integer asset id or the name of the asset as a string.  Defaults to the global asset node.
	 * @param   boolean  $group   Is id a group id?
	 *
	 * @return  boolean  True if authorised.
	 *
	 * @since   3.6
	 */
	public function isAllowed($id, $action, $asset = null, $group = false)
	{
		// Sanitise inputs.
		$id = (int) $id;

		if ($group)
		{
			$identities = JUserHelper::getGroupPath($id);
		}
		else
		{
			// Get all groups against which the user is mapped.
			$identities = JUserHelper::getGroupsByUser($id);
			array_unshift($identities, $id * -1);
		}

		$action = strtolower(preg_replace('#[\s\-]+#', '.', trim($action)));

		if (isset($asset))
		{
			$this->set('assetId', $asset);
		}

		$asset = strtolower(preg_replace('#[\s\-]+#', '.', trim($this->assetId)));

		// Default to the root asset node.
		if (empty($asset))
		{
			$assets = JTable::getInstance('Asset', 'JTable', array('dbo' => $this->db));
			$asset = $assets->getRootId();
		}

		// Get the rules for the asset recursively to root if not already retrieved.
		if (empty(self::$assetRules[$asset]))
		{
			self::$assetRules[$asset] = $this->getRules(true, $identities, $action);
		}

		return self::$assetRules[$asset]->allow($action, $identities);
	}

	/**
	 * Speed enhanced permission lookup function
	 * Returns JAccessRules object for an asset.  The returned object can optionally hold
	 * only the rules explicitly set for the asset or the summation of all inherited rules from
	 * parent assets and explicit rules.
	 *
	 * @param   boolean       $recursive  True to return the rules object with inherited rules.
	 * @param   array         $groups     Array of group ids to get permissions for
	 * @param   string        $action     Action name to limit results
	 *
	 * @return  JAccessRules   JAccessRules object for the asset.
	 */
	public function getRules($recursive = false, $groups = null, $action = null )
	{
		// Make a copy for later
		$actionForCache = $action;

		$cacheId = $this->getCacheId($recursive, $groups, $actionForCache);

		if (!isset(self::$permCache[$cacheId]))
		{
			$result = $this->getAssetPermissions($recursive, $groups, $actionForCache);

			// If no result get all permisions for root node and cache it!
			if ($recursive && empty($result))
			{
				if (!isset(self::$rootAsset))
				{
					$this->getRootAssetPermissions();
				}

				$result = self::$rootAsset;
			}

			self::$permCache[$cacheId] = $this->mergePermissionsRules($result);
		}

		// Instantiate and return the JAccessRules object for the asset rules.
		$this->rules->mergeCollection(self::$permCache[$cacheId]);
		$rules = $this->rules;

		// If action was set return only this action's result
		if (isset($action) && isset($this->rules[$action]))
		{
			$rules = array($action => $this->rules[$action]);
		}


		return $rules;
	}

	/**
	 * Calculate internal cache id
	 *
	 * @param   boolean  $recursive  True to return the rules object with inherited rules.
	 * @param   array    $groups     Array of group ids to get permissions for
	 * @param   string   &$action    Action name used for id calculation
	 *
	 * @return string
	 */

	private function getCacheId($recursive, $groups, &$action)
	{
		// We are optimizing only view for frontend, otherwise 1 query for all actions is faster globaly due to cache
		if ($action == 'core.view')
		{
			// If we have all actions query already take data from cache
			if (isset(self::$permCache[md5(serialize(array($this->assetId, $recursive, $groups, null)))]))
			{
				$action = null;
			}
		}
		else
		{
			// Don't use action in cacheId calc and query - faster with multiple actions
			$action = null;
		}

		$cacheId = md5(serialize(array($this->assetId, $recursive, $groups, $action)));

		return $cacheId;
	}

	/**
	 * Look for permissions based on asset id.
	 *
	 * @param   boolean  $recursive  True to return the rules object with inherited rules.
	 * @param   array    $groups     Array of group ids to get permissions for
	 * @param   string   $action     Action name to limit results
	 *
	 * @return mixed   Db query result - the return value or null if the query failed.
	 */
	public  function getAssetPermissions($recursive = false, $groups = array(), $action = null)
	{
		$db = JFactory::getDbo();
		$query = $db->getQuery(true);

		// Build the database query to get the rules for the asset.
		$query->from('#__assets AS a');

		// If we want the rules cascading up to the global asset node we need a self-join.
		if ($recursive)
		{
			$query->select('b.id, b.rules, p.permission, p.value, p.group');
			$query->from('#__assets AS b');
			$query->where('a.lft BETWEEN b.lft AND b.rgt');
			$query->order('b.lft');

			$conditions = 'ON b.id = p.assetid ';
		}
		else
		{
			$query->select('a.id, a.rules, p.permission, p.value, p.group');

			$conditions = 'ON a.id = p.assetid ';
		}

		if (isset($groups) && $groups != array())
		{
			if (is_string($groups))
			{
				$groups = array($groups);
			}

			$counter   = 1;
			$allGroups = count($groups);

			$groupQuery = ' AND (';

			foreach ($groups AS $group)
			{
				$groupQuery .= 'p.group = ' . $db->quote((string) $group);
				$groupQuery .= ($counter < $allGroups) ? ' OR ' : ' ) ';
				$counter++;
			}

			$conditions .= $groupQuery;
		}

		if (isset($action))
		{
			$conditions .= ' AND p.permission = ' . $db->quote((string) $action) . ' ';
		}

		$query->leftJoin('#__permissions AS p ' . $conditions);

		// If the asset identifier is numeric assume it is a primary key, else lookup by name.
		if (is_numeric($this->assetId))
		{
			$query->where('a.id = ' . (int) $this->assetId);
		}
		else
		{
			$query->where('a.name = ' . $db->quote((string) $this->assetId));
		}

		$db->setQuery($query);
		$result = $db->loadObjectList();

		return $result;
	}

	public function getRootAssetPermissions()
	{
		$db = JFactory::getDbo();

		$query = $db->getQuery(true);
		$query  ->select('b.id, b.rules, p.permission, p.value, p.group')
				->from('#__assets AS b')
				->leftJoin('#__permissions AS p ON b.id = p.assetid')
				->where('b.parent_id=0');
		$db->setQuery($query);

		self::$rootAsset  = $db->loadObjectList();

		return self::$rootAsset;
	}

	/**
	 * Merge new permissions with old rules from assets table for backwards compatibility
	 */
	private function mergePermissionsRules($results)
	{
		$mergedResult = array();

		foreach ($results AS $result)
		{
			if (isset($result->permission) && !empty($result->permission))
			{
				if (!isset($mergedResult[$result->id]))
				{
					$mergedResult[$result->id] = array();
				}

				if (!isset($mergedResult[$result->id][$result->permission]))
				{
					$mergedResult[$result->id][$result->permission] = array();
				}

				$mergedResult[$result->id][$result->permission][$result->group] = (int) $result->value;
			}
			elseif (isset($result->rules) && $result->rules != '{}')
			{
				$mergedResult[$result->id] = json_decode((string) $result->rules, true);
			}
		}

		$mergedResult = array_values($mergedResult);

		return $mergedResult;
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
		$groups = JUserHelper::getGroupsByUser($userId);

		// Only load the view levels once.
		if (empty(self::$viewLevels))
		{
			// Get a database object.
			$db = JFactory::getDbo();

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
	 * @deprecated  12.3 (Platform) & 4.0 (CMS)  Use JAccess::getActionsFromFile or JAccess::getActionsFromData instead.
	 * @codeCoverageIgnore
	 */
	public static function getActions($component, $section = 'component')
	{
		JLog::add(__METHOD__ . ' is deprecated. Use JAccess::getActionsFromFile or JAccess::getActionsFromData instead.', JLog::WARNING, 'deprecated');

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
		if (!is_file($file) || !is_readable($file))
		{
			// If unable to find the file return false.
			return false;
		}
		else
		{
			// Else return the actions from the xml.
			$xml = simplexml_load_file($file);

			return self::getActionsFromData($xml, $xpath);
		}
	}

	/**
	 * Method to return a list of actions from a string or from an xml for which permissions can be set.
	 *
	 * @param   string|SimpleXMLElement  $data   The XML string or an XML element.
	 * @param   string                   $xpath  An optional xpath to search for the fields.
	 *
	 * @return  boolean|array   False if case of error or the list of actions available.
	 *
	 * @since   12.1
	 */
	public static function getActionsFromData($data, $xpath = "/access/section[@name='component']/")
	{
		// If the data to load isn't already an XML element or string return false.
		if ((!($data instanceof SimpleXMLElement)) && (!is_string($data)))
		{
			return false;
		}

		// Attempt to load the XML if a string.
		if (is_string($data))
		{
			try
			{
				$data = new SimpleXMLElement($data);
			}
			catch (Exception $e)
			{
				return false;
			}

			// Make sure the XML loaded correctly.
			if (!$data)
			{
				return false;
			}
		}

		// Initialise the actions array
		$actions = array();

		// Get the elements from the xpath
		$elements = $data->xpath($xpath . 'action[@name][@title][@description]');

		// If there some elements, analyse them
		if (!empty($elements))
		{
			foreach ($elements as $action)
			{
				// Add the action to the actions array
				$actions[] = (object) array(
					'name' => (string) $action['name'],
					'title' => (string) $action['title'],
					'description' => (string) $action['description']
				);
			}
		}

		// Finally return the actions array
		return $actions;
	}

	/**
	 * Method to check if a user is authorised to perform an action, optionally on an asset.
	 *
	 * @param   integer  $userId  Id of the user for which to check authorisation.
	 * @param   string   $action  The name of the action to authorise.
	 * @param   mixed    $asset   Integer asset id or the name of the asset as a string.  Defaults to the global asset node.
	 *
	 * @return  boolean  True if authorised.
	 *
	 * @since   11.1
	 * @deprecated  Use isAllowed instead
	 */
	public static function check($userId, $action, $asset = null)
	{
		$rules  = new JAccessRules();
		$access = new JAccess($asset, $rules);

		return $access->isAllowed($userId, $action, $asset, false);
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
	 * @deprecated  Use isAllowed instead
	 */
	public static function checkGroup($groupId, $action, $asset = null)
	{
		$rules  = new JAccessRules();
		$access = new JAccess($asset, $rules);

		return $access->isAllowed($groupId, $action, $asset, false);
	}

	/**
	 * Method to return the JAccessRules object for an asset.  The returned object can optionally hold
	 * only the rules explicitly set for the asset or the summation of all inherited rules from
	 * parent assets and explicit rules.
	 *
	 * @param   mixed    $asset      Integer asset id or the name of the asset as a string.
	 * @param   boolean  $recursive  True to return the rules object with inherited rules.
	 *
	 * @return  JAccessRules   JAccessRules object for the asset.
	 *
	 * @since   11.1
	 * @deprecated  Use getRules instead
	 */
	public static function getAssetRules($asset, $recursive = false)
	{
		$rules  = new JAccessRules();
		$access = new JAccess($asset, $rules);

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
		return JUserHelper::getGroupTitle($groupId);
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
		return JUserHelper::getGroupsByUser($userId, $recursive);
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
		return JUserHelper::getUsersByGroup($groupId, $recursive);
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
		return JUserHelper::getGroupPath($groupId);
	}
}
