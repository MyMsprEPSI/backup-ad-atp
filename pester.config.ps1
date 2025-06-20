@{
    TestPath = "Tests"
    OutputPath = "Tests\Results"
    IncludeTags = @()
    ExcludeTags = @()
    CodeCoverage = $true
    CodeCoverageOutputPath = "Tests\Coverage"
    RunSettings = @{
        "RunAs" = "Administrator"
    }
}