#!/usr/bin/python
#
# Copyright 2010 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

"""Template based text parser.

This module implements a parser, intended to be used for converting
human readable text, such as command output from a router CLI, into
a list of records, containing values extracted from the input text.

A simple template language is used to describe a state machine to
parse a specific type of text input, returning a record of values
for each input entity.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import getopt
import inspect
import re
import string
import sys
from builtins import object   # pylint: disable=redefined-builtin
from builtins import str      # pylint: disable=redefined-builtin
from builtins import zip      # pylint: disable=redefined-builtin

import six
import pprint


class Error(Exception):
  """Base class for errors."""


class Usage(Exception):
  """Error in command line execution."""


class TextFSMError(Error):
  """Error in the FSM state execution."""


class TextFSMTemplateError(Error):
  """Errors while parsing templates."""


# The below exceptions are internal state change triggers
# and not used as Errors.
class FSMAction(Exception):
  """Base class for actions raised with the FSM."""


class SkipRecord(FSMAction):
  """Indicate a record is to be skipped."""


class SkipValue(FSMAction):
  """Indicate a value is to be skipped."""


class TextFSMOptions(object):
  """Class containing all valid TextFSMValue options.

  Each nested class here represents a TextFSM option. The format
  is "option<name>".
  Each class may override any of the methods inside the OptionBase class.

  A user of this module can extend options by subclassing
  TextFSMOptionsBase, adding the new option class(es), then passing
  that new class to the TextFSM constructor with the 'option_class'
  argument.
  """

  class OptionBase(object):
    """Factory methods for option class.

    Attributes:
      name: The name of the option.
      value: A TextFSMValue, the parent Value.
    """

    def __init__(self, value):
      self.value = value

    @property
    def name(self):
      return self.__class__.__name__.replace('option', '')

    def OnCreateOptions(self):
      """Called after all options have been parsed for a Value."""

    def OnClearVar(self):
      """Called when value has been cleared."""

    def OnClearAllVar(self):
      """Called when a value has clearalled."""

    def OnAssignVar(self):
      """Called when a matched value is being assigned."""

    def OnGetValue(self):
      """Called when the value name is being requested."""

    def OnSaveRecord(self):
      """Called just prior to a record being committed."""

  @classmethod
  def ValidOptions(cls):
    """Returns a list of valid option names."""
    valid_options = []
    for obj_name in dir(cls):
      obj = getattr(cls, obj_name)
      if inspect.isclass(obj) and issubclass(obj, cls.OptionBase):
        valid_options.append(obj_name)
    return valid_options

  @classmethod
  def GetOption(cls, name):
    """Returns the class of the requested option name."""
    return getattr(cls, name)

  class Required(OptionBase):
    """The Value must be non-empty for the row to be recorded."""

    def OnSaveRecord(self):
      if not self.value.value:
        raise SkipRecord

  class Filldown(OptionBase):
    """Value defaults to the previous line's value."""

    def OnCreateOptions(self):
      self._myvar = None

    def OnAssignVar(self):
      self._myvar = self.value.value

    def OnClearVar(self):
      self.value.value = self._myvar

    def OnClearAllVar(self):
      self._myvar = None

  class Fillup(OptionBase):
    """Like Filldown, but upwards until it finds a non-empty entry."""

    def OnAssignVar(self):
      # If value is set, copy up the results table, until we
      # see a set item.
      if self.value.value:
        # Get index of relevant result column.
        value_idx = self.value.fsm.values.index(self.value)
        # Go up the list from the end until we see a filled value.
        # pylint: disable=protected-access
        for result in reversed(self.value.fsm._result):
          if result[value_idx]:
            # Stop when a record has this column already.
            break
          # Otherwise set the column value.
          result[value_idx] = self.value.value

  class Key(OptionBase):
    """Value constitutes part of the Key of the record."""

  class List(OptionBase):
    r"""
    Value takes the form of a list.

    If the value regex contains nested match groups in the form (?P<name>regex),
    instead of adding a string to the list, we add a dictionary of the groups.

    Eg.
    Value List ((?P<name>\w+)\s+(?P<age>\d+)) would create results like:
        [{'name': 'Bob', 'age': 32}]

    Do not give nested groups the same name as other values in the template.
    """

    def OnCreateOptions(self):
      self.OnClearAllVar()

    def OnAssignVar(self):
      # Nested matches will have more than one match group
      if self.value.compiled_regex.groups > 1:
        match = self.value.compiled_regex.match(self.value.value)
      else:
        match = None
      # If the List-value regex has match-groups defined, add the resulting
      # dict to the list. Otherwise, add the string that was matched
      if match and match.groupdict():
        self._value.append(match.groupdict())
      elif self.value.value is not None:
        self._value.append(self.value.value)
      else:
        self._value.append(self.value.fsm._default)

    def OnClearVar(self):
      if 'Filldown' not in self.value.OptionNames():
        self._value = []

    def OnClearAllVar(self):
      self._value = []

    def OnSaveRecord(self):
      self.value.value = list(self._value)

  class NonEmptyList(List):
    def OnSaveRecord(self):
      self.value.value = list(self._value)
      if not len(self.value.value):
        self.value.value = None

  class Integer(OptionBase):
    def OnAssignVar(self):
      self.value.value = int(self.value.value)

  class Float(OptionBase):
    def OnAssignVar(self):
      self.value.value = float(self.value.value)

class TextFSMValue(object):
  """A TextFSM value.

  A value has syntax like:

  'Value Filldown,Required helloworld (.*)'

  Where 'Value' is a keyword.
  'Filldown' and 'Required' are options.
  'helloworld' is the value name.
  '(.*) is the regular expression to match in the input data.

  Attributes:
    compiled_regex: (regexp), Compiled regex for nested matching of List values.
    max_name_len: (int), maximum character length os a variable name.
    name: (str), Name of the value.
    options: (list), A list of current Value Options.
    regex: (str), Regex which the value is matched on.
    template: (str), regexp with named groups added.
    fsm: A TextFSMBase(), the containing FSM.
    value: (str), the current value.
  """
  # The class which contains valid options.

  def __init__(self, fsm=None, max_name_len=48, options_class=None):
    """Initialise a new TextFSMValue."""
    self.max_name_len = max_name_len
    self.name = None
    self.options = []
    self.regex = None
    self.value = None
    self.fsm = fsm
    self._options_cls = options_class

  def AssignVar(self, value):
    """Assign a value to this Value."""
    self.value = value
    # Call OnAssignVar on options.
    _ = [option.OnAssignVar() for option in self.options]

  def ClearVar(self):
    """Clear this Value."""
    self.value = None
    # Call OnClearVar on options.
    _ = [option.OnClearVar() for option in self.options]

  def ClearAllVar(self):
    """Clear this Value."""
    self.value = None
    # Call OnClearAllVar on options.
    _ = [option.OnClearAllVar() for option in self.options]

  def Header(self):
    """Fetch the header name of this Value."""
    # Call OnGetValue on options.
    _ = [option.OnGetValue() for option in self.options]
    return self.name

  def OptionNames(self):
    """Returns a list of option names for this Value."""
    return [option.name for option in self.options]

  def Parse(self, value):
    """Parse a 'Value' declaration.

    Args:
      value: String line from a template file, must begin with 'Value '.

    Raises:
      TextFSMTemplateError: Value declaration contains an error.

    """

    value_line = value.split(' ')
    if len(value_line) < 3:
      raise TextFSMTemplateError('Expect at least 3 tokens on line.')

    if not value_line[2].startswith('('):
      # Options are present
      options = value_line[1]
      for option in options.split(','):
        self._AddOption(option)
      # Call option OnCreateOptions callbacks
      _ = [option.OnCreateOptions() for option in self.options]

      self.name = value_line[2]
      self.regex = ' '.join(value_line[3:])
    else:
      # There were no valid options, so there are no options.
      # Treat this argument as the name.
      self.name = value_line[1]
      self.regex = ' '.join(value_line[2:])

    if len(self.name) > self.max_name_len:
      raise TextFSMTemplateError(
          "Invalid Value name '%s' or name too long." % self.name)

    if (not re.match(r'^\(.*\)$', self.regex) or
        self.regex.count('(') != self.regex.count(')')):
      raise TextFSMTemplateError(
          "Value '%s' must be contained within a '()' pair." % self.regex)

    self.template = re.sub(r'^\(', '(?P<%s>' % self.name, self.regex)

    # Compile and store the regex object only on List-type values for use in
    # nested matching
    if any([isinstance(x, TextFSMOptions.List) for x in self.options]):
      try:
        self.compiled_regex = re.compile(self.regex)
      except re.error as e:
        raise TextFSMTemplateError(str(e))

  def _AddOption(self, name):
    """Add an option to this Value.

    Args:
      name: (str), the name of the Option to add.

    Raises:
      TextFSMTemplateError: If option is already present or
        the option does not exist.
    """

    # Check for duplicate option declaration
    if name in [option.name for option in self.options]:
      raise TextFSMTemplateError('Duplicate option "%s"' % name)

    # Create the option object
    try:
      option = self._options_cls.GetOption(name)(self)
    except AttributeError:
      raise TextFSMTemplateError('Unknown option "%s"' % name)

    self.options.append(option)

  def OnSaveRecord(self):
    """Called just prior to a record being committed."""
    _ = [option.OnSaveRecord() for option in self.options]

  def __str__(self):
    """Prints out the FSM Value, mimic the input file."""

    if self.options:
      return 'Value %s %s %s' % (
          ','.join(self.OptionNames()),
          self.name,
          self.regex)
    else:
      return 'Value %s %s' % (self.name, self.regex)


class CopyableRegexObject(object):
  """Like a re.RegexObject, but can be copied."""

  def __init__(self, pattern):
    self.pattern = pattern
    self.regex = re.compile(pattern)

  def match(self, *args, **kwargs):
    return self.regex.match(*args, **kwargs)

  def sub(self, *args, **kwargs):
    return self.regex.sub(*args, **kwargs)

  def __copy__(self):
    return CopyableRegexObject(self.pattern)

  def __deepcopy__(self, unused_memo):
    return self.__copy__()


class TextFSMRule(object):
  """A rule in each FSM state.

  A value has syntax like:

      ^<regexp> -> Next.Record State2

  Where '<regexp>' is a regular expression.
  'Next' is a Line operator.
  'Record' is a Record operator.
  'State2' is the next State.

  Attributes:
    match: Regex to match this rule.
    regex: match after template substitution.
    line_op: Operator on input line on match.
    record_op: Operator on output record on match.
    new_state: Label to jump to on action
    regex_obj: Compiled regex for which the rule matches.
    line_num: Integer row number of Value.
  """
  # Implicit default is '(regexp) -> Next.NoRecord'
  MATCH_ACTION = re.compile(r'(?P<match>.*)(\s->(?P<action>.*))')

  # The structure to the right of the '->'.
  LINE_OP = ('Continue', 'Next', 'Error', 'Retain')
  RECORD_OP = ('Clear', 'Clearall', 'Record', 'NoRecord')

  # Line operators.
  LINE_OP_RE = '(?P<ln_op>%s)' % '|'.join(LINE_OP)
  # Record operators.
  RECORD_OP_RE = '(?P<rec_op>%s)' % '|'.join(RECORD_OP)
  # Line operator with optional record operator.
  OPERATOR_RE = r'(%s(\.%s)?)' % (LINE_OP_RE, RECORD_OP_RE)
  # New State or 'Error' string.
  NEWSTATE_RE = r'(?P<new_state>\w+|\".*\")'

  # Compound operator (line and record) with optional new state.
  ACTION_RE = re.compile(r'\s+%s(\s+%s)?$' % (OPERATOR_RE, NEWSTATE_RE))
  # Record operator with optional new state.
  ACTION2_RE = re.compile(r'\s+%s(\s+%s)?$' % (RECORD_OP_RE, NEWSTATE_RE))
  # Default operators with optional new state.
  ACTION3_RE = re.compile(r'(\s+%s)?$' % (NEWSTATE_RE))

  def __init__(self, line, line_num=-1, var_map=None):
    """Initialise a new rule object.

    Args:
      line: (str), a template rule line to parse.
      line_num: (int), Optional line reference included in error reporting.
      var_map: Map for template (${var}) substitutions.

    Raises:
      TextFSMTemplateError: If 'line' is not a valid format for a Value entry.
    """
    self.match = ''
    self.regex = ''
    self.regex_obj = None
    self.line_op = ''              # Equivalent to 'Next'.
    self.record_op = ''            # Equivalent to 'NoRecord'.
    self.new_state = ''            # Equivalent to current state.
    self.line_num = line_num

    line = line.strip()
    if not line:
      raise TextFSMTemplateError('Null data in FSMRule. Line: %s'
                                 % self.line_num)

    # Is there '->' action present.
    match_action = self.MATCH_ACTION.match(line)
    if match_action:
      self.match = match_action.group('match')
    else:
      self.match = line

    # Replace ${varname} entries.
    self.regex = self.match
    if var_map:
      try:
        self.regex = string.Template(self.match).substitute(var_map)
      except (ValueError, KeyError):
        raise TextFSMTemplateError(
            "Duplicate or invalid variable substitution: '%s'. Line: %s." %
            (self.match, self.line_num))

    try:
      # Work around a regression in Python 2.6 that makes RE Objects uncopyable.
      self.regex_obj = CopyableRegexObject(self.regex)
    except re.error:
      raise TextFSMTemplateError(
          "Invalid regular expression: '%s'. Line: %s." %
          (self.regex, self.line_num))

    # No '->' present, so done.
    if not match_action:
      return

    # Attempt to match line.record operation.
    action_re = self.ACTION_RE.match(match_action.group('action'))
    if not action_re:
      # Attempt to match record operation.
      action_re = self.ACTION2_RE.match(match_action.group('action'))
      if not action_re:
        # Math implicit defaults with an optional new state.
        action_re = self.ACTION3_RE.match(match_action.group('action'))
        if not action_re:
          # Last attempt, match an optional new state only.
          raise TextFSMTemplateError("Badly formatted rule '%s'. Line: %s." %
                                     (line, self.line_num))

    # We have an Line operator.
    if 'ln_op' in action_re.groupdict() and action_re.group('ln_op'):
      self.line_op = action_re.group('ln_op')

    # We have a record operator.
    if 'rec_op' in action_re.groupdict() and action_re.group('rec_op'):
      self.record_op = action_re.group('rec_op')

    # A new state was specified.
    if 'new_state' in action_re.groupdict() and action_re.group('new_state'):
      self.new_state = action_re.group('new_state')

    # Only 'Next' (or implicit 'Next') line operator can have a new_state.
    # But we allow error to have one as a warning message so we are left
    # checking that Continue does not.
    if self.line_op == 'Continue' and self.new_state:
      raise TextFSMTemplateError(
          "Action '%s' with new state %s specified. Line: %s."
          % (self.line_op, self.new_state, self.line_num))

    if self.line_op == 'Retain':
      if self.record_op and self.record_op != 'Record':
        raise TextFSMTemplateError(
          "Action '%s' with record action %s specified. Line: %s."
          % (self.line_op, self.record_op, self.line_num))
      else:
        self.record_op = 'Record'

    # Check that an error message is present only with the 'Error' operator.
    if self.line_op != 'Error' and self.new_state:
      if not re.match(r'\w+', self.new_state):
        raise TextFSMTemplateError(
            'Alphanumeric characters only in state names. Line: %s.'
            % (self.line_num))

  def __str__(self):
    """Prints out the FSM Rule, mimic the input file."""

    operation = ''
    if self.line_op and self.record_op:
      operation = '.'

    operation = '%s%s%s' % (self.line_op, operation, self.record_op)

    if operation and self.new_state:
      new_state = ' ' + self.new_state
    else:
      new_state = self.new_state

    # Print with implicit defaults.
    if not (operation or new_state):
      return '  %s' % self.match

    # Non defaults.
    return '  %s -> %s%s' % (self.match, operation, new_state)


class TextFSMPostProcess(object):
  """
  Textfsm Postprocessing rule has the following syntax. PostProcessing will always beging with State PostProcess

  Each post processing rule will have the following syntax.
  *) 'Zip <Name> <Value>,[<Value>,<Value>] [ -> NextPostProcessState ]'
     Builds a new value which will be list of dictionary. The dictionary will be make of name and value of the 'Value'
     It can also move the post processing to a specific state where the newly formed group can be further processed

  *) 'Key <Value>,[<Value>,<Value>]'
     If the specified value is not found then the default will be used. Key will be constructed as the tuple of
     specified values. The final Key MUST be unique else an error will be raised.
  """
  KEY = 1
  ZIP = 2
  GROUP = 3
  SQUASH = 4

  def __init__(self, fsm, state, parts):
    self.fsm = fsm
    self.state = state
    self.parts = parts
    self.new_state = None
    self.value_name = None
    self.pp_type = None
    self.list_val = False
    log_debug("Created PPRule {} {}".format(state, parts))

  def Parse(self):
    """Parse a 'PostProcess' declaration.

    Args:
      value: String line from a template file, must begin with 'PostProcess '.

    Raises:
      TextFSMTemplateError: Value declaration contains an error.
    """
    if self.parts[0] == 'Key':
      self.pp_type = self.KEY
      vals = self.parts[1].split(',')
      for val in vals:
        if val not in self.fsm.value_map:
          raise TextFSMTemplateError('Value {} name is not found'.format(val))
      if len(self.parts) == 4:
        self.new_state = self.parts[3]
      self.parts = vals
    elif self.parts[0] == 'Zip' or self.parts[0] == 'GroupBy':
      if self.parts[0] == 'Zip':
        self.pp_type = self.ZIP
      elif self.parts[0] == 'GroupBy':
        self.pp_type = self.GROUP
      self.value_name = self.parts[1]
      vals = self.parts[2].split(',')
      for val in vals:
        val_grp_found = False
        if val not in self.fsm.value_map:
          for rules in self.fsm.post_process_states.values():
            for rule in rules:
              if val == rule.value_name:
                val_grp_found = True
        else:
            val_grp_found = True
        if not val_grp_found:
          raise TextFSMTemplateError('Value {} name is not found'.format(val))
        if self.pp_type == self.ZIP:
          num_list = 0
          for v in vals:
            for value in self.fsm.values:
              if value.name == v:
                if value.options:
                  num_list += isinstance(value.options[0], TextFSMOptions.List)
                  break
          if num_list > 0 and num_list != len(vals):
            raise TextFSMTemplateError('Zip values {} all must be List or non-List values. '
                                       'Mixing not supported. Lists {}'.format(self.parts, num_list))
          self.list_val = num_list > 0
      if len(self.parts) == 5:
        self.new_state = self.parts[4]
      self.parts = vals
    elif self.parts[0] == 'Squash':
      self.pp_type = self.SQUASH
    else:
      raise TextFSMTemplateError('Unknown post process operator {}'.format(self.parts[0]))
    return


class TextFSM(object):
  """Parses template and creates Finite State Machine (FSM).

  Attributes:
    states: (str), Dictionary of FSMState objects.
    values: (str), List of FSMVariables.
    value_map: (map), For substituting values for names in the expressions.
    header: Ordered list of values.
    state_list: Ordered list of valid states.
  """
  # Variable and State name length.
  MAX_NAME_LEN = 48
  comment_regex = re.compile(r'^\s*#')
  state_name_re = re.compile(r'^(\w+)$')
  _DEFAULT_OPTIONS = TextFSMOptions

  def __init__(self, template, options_class=_DEFAULT_OPTIONS, default='', skip_default=False):
    """Initialises and also parses the template file."""

    self._options_cls = options_class
    self.states = {}
    # Track order of state definitions.
    self.state_list = []
    self.values = []
    self.value_map = {}
    # Track where we are for error reporting.
    self._line_num = 0
    # Run FSM in this state
    self._cur_state = None
    # Name of the current state.
    self._cur_state_name = None
    self._default = default
    self._skip_default = skip_default
    if skip_default:
      self._default = object()

    self.post_process_states = {}

    # Read and parse FSM definition.
    # Restore the file pointer once done.
    try:
      self._Parse(template)
    finally:
      template.seek(0)

    # Initialise starting data.
    self.Reset()

  def __str__(self):
    """Returns the FSM template, mimicing the input file."""

    result = '\n'.join([str(value) for value in self.values])
    result += '\n'

    for state in self.state_list:
      result += '\n%s\n' % state
      state_rules = '\n'.join([str(rule) for rule in self.states[state]])
      if state_rules:
        result += state_rules + '\n'

    return result

  def Reset(self):
    """Preserves FSM but resets starting state and current record."""

    # Current state is Start state.
    self._cur_state = self.states['Start']
    self._cur_state_name = 'Start'

    # Clear table of results and current record.
    self._result = []
    self._ClearAllRecord()

  @property
  def header(self):
    """Returns header."""
    return self._GetHeader()

  def _GetHeader(self):
    """Returns header."""
    header = []
    for value in self.values:
      try:
        header.append(value.Header())
      except SkipValue:
        continue
    return header

  def _GetValue(self, name):
    """Returns the TextFSMValue object natching the requested name."""
    for value in self.values:
      if value.name == name:
        return value

  def _AppendRecord(self):
    """Adds current record to result if well formed."""

    # If no Values then don't output.
    if not self.values:
      return

    cur_record = []
    for value in self.values:
      try:
        value.OnSaveRecord()
      except SkipRecord:
        self._ClearRecord()
        return
      except SkipValue:
        continue

      # Build current record into a list.
      cur_record.append(value.value)

    # If no Values in template or whole record is empty then don't output.
    if len(cur_record) == (cur_record.count(None) + cur_record.count([])):
      return

    # Replace any 'None' entries with default value.
    for idx in range(len(cur_record)):
      if cur_record[idx] is None:
        cur_record[idx] = self._default

    self._result.append(cur_record)
    self._ClearRecord()

  def _Parse(self, template):
    """Parses template file for FSM structure.

    Args:
      template: Valid template file.

    Raises:
      TextFSMTemplateError: If template file syntax is invalid.
    """

    if not template:
      raise TextFSMTemplateError('Null template.')

    # Parse header with Variables.
    self._ParseFSMVariables(template)
    self._ParseFSMPostProcessInstructions(template)

    # Parse States.
    while self._ParseFSMState(template):
      pass

    # Validate destination states.
    self._ValidateFSM()

  def _ParseFSMVariables(self, template):
    """Extracts Variables from start of template file.

    Values are expected as a contiguous block at the head of the file.
    These will be line separated from the State definitions that follow.

    Args:
      template: Valid template file, with Value definitions at the top.

    Raises:
      TextFSMTemplateError: If syntax or semantic errors are found.
    """

    self.values = []

    for line in iter(template.readline, ''):
      self._line_num += 1
      line = line.rstrip()

      # Blank line signifies end of Value definitions.
      if not line:
        return
      if not isinstance(line, six.string_types):
        line = line.decode('utf-8')
      # Skip commented lines.
      if self.comment_regex.match(line):
        continue

      if line.startswith('Value '):
        try:
          value = TextFSMValue(
              fsm=self, max_name_len=self.MAX_NAME_LEN,
              options_class=self._options_cls)
          value.Parse(line)
        except TextFSMTemplateError as error:
          raise TextFSMTemplateError('%s Line %s.' % (error, self._line_num))

        if value.name in self.header:
          raise TextFSMTemplateError(
              "Duplicate declarations for Value '%s'. Line: %s."
              % (value.name, self._line_num))

        try:
          self._ValidateOptions(value)
        except TextFSMTemplateError as error:
          raise TextFSMTemplateError('%s Line %s.' % (error, self._line_num))

        self.values.append(value)
        self.value_map[value.name] = value.template
      # The line has text but without the 'Value ' prefix.
      elif not self.values:
        raise TextFSMTemplateError('No Value definitions found.')
      else:
        raise TextFSMTemplateError(
            'Expected blank line after last Value entry. Line: %s.'
            % (self._line_num))

  def _ValidateOptions(self, value):
    """Checks that combination of Options is valid."""
    # Always passes in base class.
    pass

  def _ParseFSMState(self, template):
    """Extracts State and associated Rules from body of template file.

    After the Value definitions the remainder of the template is
    state definitions. The routine is expected to be called iteratively
    until no more states remain - indicated by returning None.

    The routine checks that the state names are a well formed string, do
    not clash with reserved names and are unique.

    Args:
      template: Valid template file after Value definitions
      have already been read.

    Returns:
      Name of the state parsed from file. None otherwise.

    Raises:
      TextFSMTemplateError: If any state definitions are invalid.
    """

    if not template:
      return

    state_name = ''
    # Strip off extra white space lines (including comments).
    for line in iter(template.readline, ''):
      self._line_num += 1
      line = line.rstrip()
      if not isinstance(line, six.string_types):
        line = line.decode('utf-8')
      # First line is state definition
      if line and not self.comment_regex.match(line):
         # Ensure statename has valid syntax and is not a reserved word.
        if (not self.state_name_re.match(line) or
            len(line) > self.MAX_NAME_LEN or
            line in TextFSMRule.LINE_OP or
            line in TextFSMRule.RECORD_OP):
          raise TextFSMTemplateError("Invalid state name: '%s'. Line: %s"
                                     % (line, self._line_num))

        state_name = line
        if state_name in self.states:
          raise TextFSMTemplateError("Duplicate state name: '%s'. Line: %s"
                                     % (line, self._line_num))
        self.states[state_name] = []
        self.state_list.append(state_name)
        break

    # Parse each rule in the state.
    for line in template:
      self._line_num += 1
      line = line.rstrip()

      # Finish rules processing on blank line.
      if not line:
        break
      if not isinstance(line, six.string_types):
        line = line.decode('utf-8')
      if self.comment_regex.match(line):
        continue

      # A rule within a state, starts with 1 or 2 spaces, or a tab.
      if not line.startswith((' ^', '  ^', '\t^')):
        raise TextFSMTemplateError(
            "Missing white space or carat ('^') before rule. LineNum: %s Line: %s"
            % (self._line_num, line))

      self.states[state_name].append(
          TextFSMRule(line, self._line_num, self.value_map))

    return state_name

  def _ValidateFSM(self):
    """Checks state names and destinations for validity.

    Each destination state must exist, be a valid name and
    not be a reserved name.
    There must be a 'Start' state and if 'EOF' or 'End' states are specified,
    they must be empty.

    Returns:
      True if FSM is valid.

    Raises:
      TextFSMTemplateError: If any state definitions are invalid.
    """

    # Must have 'Start' state.
    if 'Start' not in self.states:
      raise TextFSMTemplateError("Missing state 'Start'.")

    # 'End/EOF' state (if specified) must be empty.
    if self.states.get('End'):
      raise TextFSMTemplateError("Non-Empty 'End' state.")

    if self.states.get('EOF'):
      raise TextFSMTemplateError("Non-Empty 'EOF' state.")

    # Remove 'End' state.
    if 'End' in self.states:
      del self.states['End']
      self.state_list.remove('End')

    # Ensure jump states are all valid.
    for state in self.states:
      for rule in self.states[state]:
        if rule.line_op == 'Error':
          continue

        if not rule.new_state or rule.new_state in ('End', 'EOF'):
          continue

        if rule.new_state not in self.states:
          raise TextFSMTemplateError(
              "State '%s' not found, referenced in state '%s'" %
              (rule.new_state, state))

    return True

  def _ParseFSMPostProcessInstructions(self, template):
    """
    Does postprocessing on Textfsm parsed data.

    Args:
      template: Valid template file, with Value definitions at the top.

    Raises:
      TextFSMTemplateError: If syntax or semantic errors are found.
    """
    self.post_process_states = {}
    reset_pos = template.tell()
    proc_state = None
    for line in iter(template.readline, ''):
      self._line_num += 1
      line = line.rstrip()

      if len(line) == 0:
        # Skip all blank lines
        continue
      if line.startswith('Start'):
        break
      if not isinstance(line, six.string_types):
        line = line.decode('utf-8')
      # Skip commented lines.
      if self.comment_regex.match(line):
        continue

      log_debug("Processing line {}".format(line))
      if line[0] != " " and line[0] != "\t":
        log_debug("Postprocessing state is {}".format(line))
        proc_state = line
        continue
      if proc_state:
        if not line.startswith(" ") and not line.startswith("  ") and line.startswith("\t"):
          raise TextFSMTemplateError('Line %s:%s inside postprocessing states must begin with 1/2 spaces or 1 tab'
                                     % (self._line_num, line))

      parts = line.strip().split(' ')
      if parts[0] == 'Squash':
        if len(parts) > 1:
          raise TextFSMTemplateError('Squash expects max 1 tokens on line %s:%s.' % (self._line_num, line))
      elif len(parts) < 2:
        raise TextFSMTemplateError('Expect at least 2 tokens on line %s:%s.' % (self._line_num, line))
      if parts[0] == 'Key' and len(parts) != 2 and len(parts) != 4:
        raise TextFSMTemplateError('Key expects max 2 tokens on line %s:%s.' % (self._line_num, line))
      if parts[0] == 'Zip':
        if len(parts) != 3 and len(parts) != 5:
          raise TextFSMTemplateError('Zip expects 3 or 5 tokens on line %s:%s.' % (self._line_num, line))
        if len(parts) == 5 and parts[3] != "->":
          raise TextFSMTemplateError('Zip with 5 tokens expects -> on line %s:%s.' % (self._line_num, line))

      rec = TextFSMPostProcess(self, proc_state, parts)
      rec.Parse()
      try:
        self.post_process_states[proc_state].append(rec)
      except KeyError:
        self.post_process_states[proc_state] = [rec]
      reset_pos = template.tell()

    if reset_pos:
      template.seek(reset_pos)

  def ParseText(self, text, eof=True):
    """Passes CLI output through FSM and returns list of tuples.

    First tuple is the header, every subsequent tuple is a row.

    Args:
      text: (str), Text to parse with embedded newlines.
      eof: (boolean), Set to False if we are parsing only part of the file.
            Suppresses triggering EOF state.

    Raises:
      TextFSMError: An error occurred within the FSM.

    Returns:
      List of Lists.
    """

    log_debug("Start parsing text using template")
    lines = []
    if text:
      lines = text.splitlines()

    for line in lines:
      self._CheckLine(line)
      if self._cur_state_name in ('End', 'EOF'):
        log_debug("Line:{} -> EOF. Stop processing".format(line))
        break

    if self._cur_state_name != 'End' and 'EOF' not in self.states and eof:
      # Implicit EOF performs Next.Record operation.
      # Suppressed if Null EOF state is instantiated.
      self._AppendRecord()

    return self._result

  def ParseTextToDicts(self, *args, **kwargs):
    """Calls ParseText and turns the result into list of dicts.

    List items are dicts of rows, dict key is column header and value is column
    value.

    Args:
      text: (str), Text to parse with embedded newlines.
      eof: (boolean), Set to False if we are parsing only part of the file.
            Suppresses triggering EOF state.

    Raises:
      TextFSMError: An error occurred within the FSM.

    Returns:
      List of dicts.
    """

    result_lists = self.ParseText(*args, **kwargs)
    result_dicts = []
    for row in result_lists:
      item = dict(zip(self.header, row))
      if self._skip_default:
        # This doesnt take care of list values. It will be removed in post processing
        item = {k: v for k, v in item.items() if (v != self._default)}
      result_dicts.append(item)
    result_dicts = self._PostProcess(result_dicts)
    return result_dicts

  def _CheckLine(self, line):
    """Passes the line through each rule until a match is made.

    Args:
      line: A string, the current input line.
    """
    for rule in self._cur_state:
      matched = self._CheckRule(rule, line)
      if matched:
        log_debug("Line:{} Matched rule:{} NextState:{}".format(line, rule, rule.new_state))
        # For Retain do not update the values. May want a record
        # without new values
        if rule.line_op != 'Retain':
          for value in matched.groupdict():
            self._AssignVar(matched, value)

        st_chg = self._Operations(rule, line)
        if rule.line_op == 'Retain':
          # Assign values in new record
          for value in matched.groupdict():
            self._AssignVar(matched, value)
        if st_chg:
          # Not a Continue so check for state transition.
          if rule.new_state:
            if rule.new_state not in ('End', 'EOF'):
              self._cur_state = self.states[rule.new_state]
            self._cur_state_name = rule.new_state
          break

  def _CheckRule(self, rule, line):
    """Check a line against the given rule.

    This is a separate method so that it can be overridden by
    a debugging tool.

    Args:
      rule: A TextFSMRule(), the rule to check.
      line: A str, the line to check.

    Returns:
      A regex match object.
    """
    return rule.regex_obj.match(line)

  def _AssignVar(self, matched, value):
    """Assigns variable into current record from a matched rule.

    If a record entry is a list then append, otherwise values are replaced.

    Args:
      matched: (regexp.match) Named group for each matched value.
      value: (str) The matched value.
    """
    _value = self._GetValue(value)
    if _value is not None:
      _value.AssignVar(matched.group(value))

  def _Operations(self, rule, line):
    """Operators on the data record.

    Operators come in two parts and are a '.' separated pair:

      Operators that effect the input line or the current state (line_op).
        'Next'      Get next input line and restart parsing (default).
        'Continue'  Keep current input line and continue resume parsing.
        'Error'     Unrecoverable input discard result and raise Error.

      Operators that affect the record being built for output (record_op).
        'NoRecord'  Does nothing (default)
        'Record'    Adds the current record to the result.
        'Clear'     Clears non-Filldown data from the record.
        'Clearall'  Clears all data from the record.

    Args:
      rule: FSMRule object.
      line: A string, the current input line.

    Returns:
      True if state machine should restart state with new line.

    Raises:
      TextFSMError: If Error state is encountered.
    """
    # First process the Record operators.
    if rule.record_op == 'Record':
      self._AppendRecord()

    elif rule.record_op == 'Clear':
      # Clear record.
      self._ClearRecord()

    elif rule.record_op == 'Clearall':
      # Clear all record entries.
      self._ClearAllRecord()

    # Lastly process line operators.
    if rule.line_op == 'Error':
      if rule.new_state:
        raise TextFSMError('Error: %s. Rule Line: %s. Input Line: %s.'
                           % (rule.new_state, rule.line_num, line))

      raise TextFSMError('State Error raised. Rule Line: %s. Input Line: %s'
                         % (rule.line_num, line))

    elif rule.line_op == 'Continue':
      # Continue with current line without returning to the start of the state.
      return False

    # Back to start of current state with a new line.
    return True

  def _ClearRecord(self):
    """Remove non 'Filldown' record entries."""
    _ = [value.ClearVar() for value in self.values]

  def _ClearAllRecord(self):
    """Remove all record entries."""
    _ = [value.ClearAllVar() for value in self.values]

  def GetValuesByAttrib(self, attribute):
    """Returns the list of values that have a particular attribute."""

    if attribute not in self._options_cls.ValidOptions():
      raise ValueError("'%s': Not a valid attribute." % attribute)

    result = []
    for value in self.values:
      if attribute in value.OptionNames():
        result.append(value.name)

    return result

  def __PostProcessState(self, results, data_path, state):
    log_debug("Path:{} State:{} Results:{}".format(data_path, state, pprint.pformat(results)))
    rules = self.post_process_states[state]
    for rule in rules:
      if rule.pp_type == rule.KEY:
        if self.__PostProcessKeyRule(results, data_path, rule):
          log_debug("Final data after processing KEY is \n" + pprint.pformat(results))
          self.__PostProcessNextState(results, data_path, rule, True)
        else:
          log_debug("No more data to process after KEY")
      elif rule.pp_type == rule.ZIP:
        if self.__PostProcessZipRule(results, data_path, rule):
          log_debug("Final data after processing ZIP is \n" + pprint.pformat(results))
          self.__PostProcessNextState(results, data_path, rule, False)
        else:
          log_debug("No more data to process after ZIP")
      elif rule.pp_type == rule.GROUP:
        if self.__PostProcessGroupRule(results, data_path, rule):
          log_debug("Final data after processing GroupBy is \n" + pprint.pformat(results))
          self.__PostProcessNextState(results, data_path, rule, False)
        else:
          log_debug("No more data to process after ZIP")
      elif rule.pp_type == rule.SQUASH:
        self.__PostProcessSquashRule(results, data_path, rule)

  def __PostProcessNextState(self, results, path, rule, use_keys):
    if rule.new_state:
      target = results
      for p in path:
        target = results[p]
      if use_keys:
        for k in target.keys():
          self.__PostProcessState(target, [k], rule.new_state)
      elif not use_keys:
        if isinstance(target, dict):
          target = [target]
        for item in target:
          if rule.new_state and rule.value_name in item:
            self.__PostProcessState(item, [rule.value_name], rule.new_state)

  def __PostProcessSquashRule(self, results, data_path, rule):
    log_debug('Post Processing SQUASH on State {} Path {}'.format(rule.state, data_path))
    new_data = results
    for k in data_path:
      new_data = new_data[k]
    # Data here can either be list of dict or a single item dict
    if isinstance(new_data, list):
      new_item = dict()
      list_info = dict()
      for val in new_data:
        for k, v in val.items():
          if k not in new_item:
            new_item[k] = v
          elif k in list_info:
            new_item[k].append(v)
          else:
            new_item[k] = [new_item.pop(k)]
            new_item[k].append(v)
            list_info[k] = True

      new_data = results
      for i, k in enumerate(data_path):
        if i != len(data_path) - 1:
          new_data = new_data[k]
        else:
          new_data[k] = new_item

  def __PostProcessGroupRule(self, results, data_path, rule):
    log_debug('Post Processing GROUP on State {} Path {}. Store result as {}'.format(rule.state, data_path,
      rule.value_name))
    work_data = results
    for k in data_path:
      work_data = work_data[k]
    # Data here can either be list of dict or a single dict
    target = work_data
    if isinstance(work_data, dict):
      work_data = [work_data]
    new_val = dict()
    rem_idx = list()
    for idx, val in enumerate(work_data):
      for k in rule.parts:
        if k not in val:
          break
        rem_idx.append(idx)
    for idx in reversed(rem_idx):
      item = work_data.pop(idx)
      key_parts = list()
      for k in rule.parts:
        key_parts.append(item.pop(k))
      if len(key_parts) > 1:
        new_val[tuple(key_parts)] = item
      else:
        new_val[key_parts[0]] = item
    if new_val:
      if isinstance(target, dict):
        target[rule.value_name] = new_val
      else:
        target.append({rule.value_name: new_val})
    return len(rem_idx) > 0

  def __PostProcessZipRule(self, results, data_path, rule):
    log_debug('Post Processing Zip on State {} with components {}. New State {}'.format(rule.state, rule.parts,
      rule.new_state))
    new_data = results
    for k in data_path:
      new_data = new_data[k]
    if not new_data:
      return False
    __sentinel = self._default
    # Data here can either be list of dict or a single dict
    if isinstance(new_data, dict):
      new_data = [new_data]
    for val in new_data:
      assert (isinstance(val, dict)), type(val)
      new_val = dict()
      for field in rule.parts:
        # Take out the values from the object into the new val dict
        if rule.list_val:
          new_val[field] = val.pop(field, list())
        else:
          new_val[field] = val.pop(field, __sentinel)
      log_debug("Extracted new item is {}".format(new_val))
      if rule.list_val:
        log_debug("Zip should be list of values")
        max_len = max(map(len, new_val.values()), default=0)
        old_len = 0
        new_len = 0
        for c in new_val.values():
          old_len += len(c)
          c.extend([__sentinel] * (max_len - len(c)))
          new_len += len(c)
        new_val_list = [dict() for _ in range(max_len)]
        for f, vs in new_val.items():
          for i, v in enumerate(vs):
            new_val_list[i][f] = v
        if old_len != new_len:
          pruned_items = list()
          for item in new_val_list:
            to_del = list()
            for k,v in item.items():
              if v is __sentinel:
                to_del.append(k)
            for k in to_del:
              del item[k]
            if item:
              pruned_items.append(item)
          new_val_list = pruned_items
        if new_val_list:
          log_debug("Zipped list is {}".format(new_val_list))
          val[rule.value_name] = new_val_list
        else:
          log_debug("No items in the zipped list")
      else:
        new_val = {k: v for k, v in new_val.items() if v is not __sentinel}
        if new_val:
          val[rule.value_name] = new_val
    return True

  def __PostProcessKeyRule(self, results, data_path, rule):
    log_debug('Post Processing KEY on State {} with components {}'.format(rule.state, rule.parts))
    new_data = results
    for k in data_path:
      new_data = new_data[k]
    if not isinstance(new_data, (list, tuple)):
      # raise TextFSMError("Cant convert non list/tuple items to dict. Rule Key %s" % rule.parts)
      new_data = [new_data]
    mod_data = dict()
    for item in new_data:
      log_debug("Processing item {}".format(item))
      components = list()
      for field in rule.parts:
        components.append(item.pop(field))
      if len(components) == 1:
        new_key = components[0]
      else:
        new_key = tuple(components)
      if not len(item):
          continue
      if new_key in mod_data:
        if not isinstance(mod_data[new_key], list):
          new_val = [mod_data.pop(new_key), item]
          mod_data[new_key] = new_val
        else:
          mod_data[new_key].append(item)
      else:
        mod_data[new_key] = item
    log_debug("Mod data now is {}".format(mod_data))
    target = results
    for k in data_path[:-1]:
      target = target[k]
    target[data_path[-1]] = mod_data
    return True

  def _PostProcess(self, results):
    if not len(self.post_process_states):
      return results

    log_debug("Begining post processing rules")
    log_debug(pprint.pformat(results))
    result_dicts = dict()
    # Post processing starts with default 'PostProcess' state
    result_dicts["PostProcess"] = results
    data_path = ["PostProcess"]
    self.__PostProcessState(result_dicts, data_path, "PostProcess")
    if self._skip_default:
      self.__removeDefaultSentinelDict(result_dicts)
    return result_dicts["PostProcess"]

  def __removeDefaultSentinelDict(self, data):
    remove_key = list()
    for k, v in data.items():
      if v is self._default:
        remove_key.append(k)
      elif isinstance(v, dict):
        self.__removeDefaultSentinelDict(v)
      elif isinstance(v, list):
        for i in v:
          if isinstance(i, dict):
            self.__removeDefaultSentinelDict(i)
    for k in remove_key:
      del data[k]

def main(argv=None):
  """Validate text parsed with FSM or validate an FSM via command line."""

  if argv is None:
    argv = sys.argv

  try:
    opts, args = getopt.getopt(argv[1:], 'h', ['help'])
  except getopt.error as msg:
    raise Usage(msg)

  for opt, _ in opts:
    if opt in ('-h', '--help'):
      print(__doc__)
      print(help_msg)
      return 0

  if not args or len(args) > 4:
    raise Usage('Invalid arguments.')

  # If we have an argument, parse content of file and display as a template.
  # Template displayed will match input template, minus any comment lines.
  with open(args[0], 'r') as template:
    fsm = TextFSM(template)
    print('FSM Template:\n%s\n' % fsm)

    if len(args) > 1:
      # Second argument is file with example cli input.
      # Prints parsed tabular result.
      with open(args[1], 'r') as f:
        cli_input = f.read()

      table = fsm.ParseText(cli_input)
      print('FSM Table:')
      result = str(fsm.header) + '\n'
      for line in table:
        result += str(line) + '\n'
      print(result, end='')

  if len(args) > 2:
    # Compare tabular result with data in third file argument.
    # Exit value indicates if processed data matched expected result.
    with open(args[2], 'r') as f:
      ref_table = f.read()

    if ref_table != result:
      print('Data mis-match!')
      return 1
    else:
      print('Data match!')

def log_debug(msg):
  'print("TFSM DEBUG ", msg)'

def parse_using_textfsm2(tmpl_file, output):
    import os
    file_location = os.path.join(os.path.dirname(__file__), '..', '..', '..')
    file_location = os.path.abspath(file_location)
    with open(os.path.join(file_location, "templates", tmpl_file)) as f:
        tmpl = TextFSM(f, default=None, skip_default=True)
        result = tmpl.ParseTextToDicts(output)
        return result

if __name__ == '__main__':
  help_msg = '%s [--help] template [input_file [output_file]]\n' % sys.argv[0]
  try:
    sys.exit(main())
  except Usage as err:
    print(err, file=sys.stderr)
    print('For help use --help', file=sys.stderr)
    sys.exit(2)
  except (IOError, TextFSMError, TextFSMTemplateError) as err:
    print(err, file=sys.stderr)
    sys.exit(2)
