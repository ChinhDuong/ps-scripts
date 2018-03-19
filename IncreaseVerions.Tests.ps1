$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.', '.'
. "$here\$sut"

Describe "Increase-Version"{
	Context "With input parameters"{
		# arrange
		$module = "."
		$assemblyInfo = "C:\Users\dev1\Source\Workspaces\VBM_BCO\VBM.BCO\SharedAssemblyInfo.cs"

		# act
		Increase-Version $module $assemblyInfo
	}
}
