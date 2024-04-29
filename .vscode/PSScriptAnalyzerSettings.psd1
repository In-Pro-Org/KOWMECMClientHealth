# PSAppDeployToolkit default rules for PSScriptAnalyser, to ensure compatibility with PowerSHell 3.0
@{
    Severity     = @(
        'Error',
        'Warning'
    );
    ExcludeRules = @(
        'PSUseDeclaredVarsMoreThanAssigments',
        'PSAvoidGlobalVars',
        'PSAvoidUsingWriteHost',
        'PSAvoidTrailingWhiteSpace',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSAvoidUsingInvokeExpression',
        'PSUseSingularNouns'
    );
    Rules        = @{
        PSUseCompatibleCmdlets = @{
            Compatibility = @('desktop-3.0-windows')
        };
    }
}
