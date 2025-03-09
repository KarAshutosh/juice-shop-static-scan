// eslint-plugin-idor-detection/lib/rules/direct-database-access.js
module.exports = {
  meta: {
    type: "suggestion",
    docs: {
      description: "Detect potential IDOR vulnerabilities through direct use of user input in database queries",
      category: "Security",
      recommended: true,
    },
    fixable: null,
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        // Check if this is a database query method
        if (isModelQueryMethod(node)) {
          // Get the argument (ID) being passed to the query
          const arg = node.arguments[0];
          
          // Check if the argument is derived from user input
          if (isUserInput(arg, context)) {
            // Check if there's no access control check
            if (!hasAccessControlCheck(context.getAncestors())) {
              context.report({
                node,
                message: "Potential IDOR: Using user input directly in database query without access control checks",
              });
            }
          }
        }
      }
    };
    
    // Helper functions
    function isModelQueryMethod(node) {
      if (!node.callee || !node.callee.property) return false;
      
      const methodName = node.callee.property.name;
      const queryMethods = ['findById', 'findOne', 'findByPk', 'get', 'one'];
      
      return queryMethods.includes(methodName);
    }
    
    function isUserInput(node, context) {
      if (!node) return false;
      
      // Direct check for req.params.id, req.query.id patterns
      if (node.type === 'MemberExpression') {
        const objectString = context.getSourceCode().getText(node);
        return /req\.params|req\.query|req\.body/.test(objectString);
      }
      
      return false;
    }
    
    function hasAccessControlCheck(ancestors) {
      if (!ancestors || ancestors.length === 0) return false;
      
      // Look through the ancestor nodes for authentication/authorization checks
      const code = ancestors.map(a => a.type === 'IfStatement' ? context.getSourceCode().getText(a.test) : '').join(' ');
      
      return /req\.user|authentication|isAuthorized|hasAccess|isAdmin/.test(code);
    }
  }
};