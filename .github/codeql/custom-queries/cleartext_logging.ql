/**
 * @name Cleartext logging of sensitive information
 * @description Logging sensitive information like passwords in cleartext is a security risk.
 * @kind problem
 * @problem.severity warning
 * @id python/custom/cleartext-logging
 * @tags security
 */

import python

from Call call, Attribute attr, Name attrName, StringLiteral stringArg
where
  // Look for calls to logger methods (e.g., logger.debug, logger.info)
  call.getFunc() = attr and
  attr.getObject() = attrName and
  attrName.getId() = "logger" and
  // Ensure we are passing a string to the logger that might contain the word "password"
  call.getAnArg() = stringArg and
  stringArg.getText().matches("%password%")
select call, "This log statement potentially logs a password in cleartext."
