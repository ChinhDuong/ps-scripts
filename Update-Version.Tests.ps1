. .\Update-Version.ps1

Describe "Update-Version"{
	Context "With input parameters"{
		# arrange
		$module = "."
		$assemblyInfo = "C:\Users\dev1\Source\Workspaces\VBM_BCO\VBM.BCO\SharedAssemblyInfo.cs"

		# act
		Update-Version $module $assemblyInfo
	}
}
