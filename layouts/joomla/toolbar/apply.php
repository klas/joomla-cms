<?php
/**
 * @package     Joomla.Site
 * @subpackage  Layout
 *
 * @copyright   Copyright (C) 2005 - 2016 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('JPATH_BASE') or die;


if (preg_match('/Joomla.submitbutton/', $displayData['doTask']))
{
	$ctrls = str_replace("Joomla.submitbutton('", '', $displayData['doTask']);
	$ctrls = str_replace("')", '', $ctrls);
	$ctrls = str_replace(";", '', $ctrls);

	JHtml::_('behavior.core');
	JHtml::_('jquery.framework');
	$options = array('task' => $ctrls);
	JFactory::getDocument()->addScriptOptions('keySave', $options);
}
else
{
	JHtml::_('behavior.core');
}

$doTask   = $displayData['doTask'];
$class    = $displayData['class'];
$text     = $displayData['text'];
$btnClass = $displayData['btnClass'];
?>
<button onclick="<?php echo $doTask; ?>" class="<?php echo $btnClass; ?>">
	<span class="<?php echo trim($class); ?>"></span>
	<?php echo $text; ?>
</button>
