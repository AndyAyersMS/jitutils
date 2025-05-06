// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Azure;
using Azure.AI.OpenAI;
using Azure.Core;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Emit;
using Microsoft.CodeAnalysis.MSBuild;
using Microsoft.Extensions.DependencyModel;
using Microsoft.Extensions.DependencyModel.Resolution;
using OpenAI.Chat;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace LLMFuzz
{
    public class MutateTestException : Exception { }

    enum ExecutionResultKind
    {
        RanNormally,
        HadFailures,
        CompilationException,
        CompilationFailed,
        MutantCompilationException,
        MutantCompilationFailed,
        SizeTooLarge,
        RanTooLong,
        LoadFailed,
        ThrewException,
        BadExitCode,
        MutantLoadFailed,
        MutantThrewException,
        MutantBadExitCode,
        HasDependentProjects,
        NoFileAccess,
        BadLLMResponse,
        SkipSpecialCase
    }

    struct ExecutionResult
    {
        public ExecutionResultKind kind;
        public int value;

        public bool Success => kind == ExecutionResultKind.RanNormally;
        public bool OriginalCompileFailed => kind == ExecutionResultKind.CompilationFailed || kind == ExecutionResultKind.CompilationException
            || kind == ExecutionResultKind.HasDependentProjects || kind == ExecutionResultKind.SkipSpecialCase;

        public bool CompileFailed => kind == ExecutionResultKind.CompilationFailed || kind == ExecutionResultKind.CompilationException
            || kind == ExecutionResultKind.MutantCompilationFailed || kind == ExecutionResultKind.MutantCompilationException;

        public bool AssemblyLoadFailed => kind == ExecutionResultKind.LoadFailed || kind == ExecutionResultKind.MutantLoadFailed;

        public bool OriginalRunFailed => kind == ExecutionResultKind.ThrewException || kind == ExecutionResultKind.BadExitCode;

        public bool MutantRunFailed => kind == ExecutionResultKind.MutantThrewException || kind == ExecutionResultKind.MutantBadExitCode;

        public bool NoMutationsAttempted => kind == ExecutionResultKind.SizeTooLarge || kind == ExecutionResultKind.RanTooLong || kind == ExecutionResultKind.BadLLMResponse;

        public override string ToString()
        {
            switch (kind)
            {
                case ExecutionResultKind.RanNormally: return "ran normally";
                case ExecutionResultKind.HadFailures: return "had failures";
                case ExecutionResultKind.CompilationException: return "base compile caused exception";
                case ExecutionResultKind.CompilationFailed: return "base compilation failed";
                case ExecutionResultKind.MutantCompilationException: return "mutant compilation caused exception";
                case ExecutionResultKind.MutantCompilationFailed: return "mutant compilation failed";
                case ExecutionResultKind.SizeTooLarge: return $"test case size {value} bytes exceeds current size limit {Program.SizeLimit} bytes";
                case ExecutionResultKind.RanTooLong: return $"base compile or excution time {value} ms exceeds current time limit {Program.TimeLimit} ms";
                case ExecutionResultKind.LoadFailed: return "base assembly load failed";
                case ExecutionResultKind.ThrewException: return "base execution threw an exception";
                case ExecutionResultKind.BadExitCode: return $"base execution returned bad exit code {value}";
                case ExecutionResultKind.MutantThrewException: return "mutant execution threw exception";
                case ExecutionResultKind.MutantLoadFailed: return $"mutant assembly load failed";
                case ExecutionResultKind.MutantBadExitCode: return $"mutant execution returned bad exit code {value}";
                case ExecutionResultKind.HasDependentProjects: return "base project has dependent projects";
                case ExecutionResultKind.NoFileAccess: return "file access error";
                case ExecutionResultKind.BadLLMResponse: return "Bad LLM response";
                case ExecutionResultKind.SkipSpecialCase: return "test is on internal skip list";
            }

            return "unknown?";
        }
    }

    internal sealed class Program
    {
        public static int SizeLimit;
        public static int TimeLimit;
        public static int VersionLimit = 10;
        public static bool Verbose;

        public static string Core_Root = Environment.GetEnvironmentVariable("CORE_ROOT") ?? throw new InvalidOperationException("Environment variable 'CORE_ROOT' is not set.");

        private static readonly CSharpCompilationOptions DebugOptions =
            new CSharpCompilationOptions(OutputKind.ConsoleApplication, concurrentBuild: false, optimizationLevel: OptimizationLevel.Debug).WithAllowUnsafe(true);

        // OutputKind.DynamicallyLinkedLibrary
        private static readonly CSharpCompilationOptions ReleaseOptions =
            new CSharpCompilationOptions(OutputKind.ConsoleApplication, concurrentBuild: false, optimizationLevel: OptimizationLevel.Release).WithAllowUnsafe(true);

        private static readonly CSharpParseOptions ParseOptions = new CSharpParseOptions(LanguageVersion.Latest);

        private static readonly MetadataReference[] References =
        {
            MetadataReference.CreateFromFile(Path.Combine(Core_Root, "System.Private.CoreLib.dll")),
            MetadataReference.CreateFromFile(Path.Combine(Core_Root, "System.Runtime.dll")),
            MetadataReference.CreateFromFile(Path.Combine(Core_Root, "System.Console.dll")),
            MetadataReference.CreateFromFile(Path.Combine(Core_Root, "System.Linq.dll")),
            MetadataReference.CreateFromFile(Path.Combine(Core_Root, "System.Collections.dll")),
            MetadataReference.CreateFromFile(Path.Combine(Core_Root, "System.Collections.Immutable.dll")),
            MetadataReference.CreateFromFile(Path.Combine(Core_Root, "xunit.core.dll"))
        };

        public Random _random;
        private bool _quiet;

        public static void Main(string[] args)
        {
            var p = new Program();
            p._random = new Random(42);
            p._quiet = true;

            SizeLimit = 10000;
            TimeLimit = 10000;
            Verbose = true;

            p.Run();
        }

        public int Run()
        {
            int total = 0;
            int skipped = 0;
            int failed = 0;
            int succeeded = 0;
            int variantTotal = 0;
            int variantFailedToCompile = 0;
            int variantFailedToRun = 0;

            string inputFilePath = Environment.GetEnvironmentVariable("TEST_PATH") ?? throw new InvalidOperationException("Environment variable 'TEST_PATH' is not set.");
            bool recursive = Directory.Exists(inputFilePath);
            if (recursive)
            {
                string suffix = ".cs";
                var inputFiles = Directory.EnumerateFiles(inputFilePath, "*", SearchOption.AllDirectories)
                                    .Where(s => (s.EndsWith(suffix)));

                Console.WriteLine($"Processing {inputFiles.Count()} files\n");

                foreach (var subInputFile in inputFiles)
                {
                    // hack to avoid reprocessing earlier outputs
                    if (subInputFile.Contains("-"))
                    {
                        skipped++;
                        continue;
                    }
                    total++;

                    int subVariantTotal = 0;
                    int subVariantFailedToCompile = 0;
                    int subVariantFailedToRun = 0;

                    ExecutionResult result = MutateOneTestFile(subInputFile, ref subVariantTotal, ref subVariantFailedToCompile, ref subVariantFailedToRun);

                    if (result.Success)
                    {
                        succeeded++;
                    }
                    else
                    {
                        if (result.OriginalCompileFailed || result.OriginalRunFailed || result.NoMutationsAttempted)
                        {
                            skipped++;
                        }
                        else
                        {
                            if (subVariantFailedToRun > 0)
                            {
                                failed++;
                            }

                            if (subVariantFailedToRun > 0)
                            {
                                int successes = subVariantTotal - subVariantFailedToCompile - subVariantFailedToRun;
                                Console.WriteLine($"// {subInputFile}: {subVariantTotal} variants, {successes} passed" +
                                    $" [{subVariantFailedToCompile} did not compile, {subVariantFailedToRun} did not run correctly]");
                            }
                        }
                    }

                    variantTotal += subVariantTotal;
                    variantFailedToCompile += subVariantFailedToCompile;
                    variantFailedToRun += subVariantFailedToRun;
                }

                Console.WriteLine($"Final Results: {total} files, {succeeded} succeeded, {skipped} skipped, {failed} failed");
                Console.WriteLine($"{variantTotal} total variants attempted,  {variantFailedToCompile} did not compile, {variantFailedToRun} did not run.");

                if (failed == 0)
                {
                    return 100;
                }
                else
                {
                    return -1;
                }
            }
            else
            {
                Console.WriteLine($"// *** LLM-Fuzz {inputFilePath} ***");

                ExecutionResult result = MutateOneTestFile(inputFilePath, ref variantTotal, ref variantFailedToCompile, ref variantFailedToRun);

                if (result.Success)
                {
                    Console.WriteLine($"// {inputFilePath}: {variantTotal} variants, all passed");
                    succeeded++;
                    return 100;
                }

                if (result.OriginalCompileFailed || result.OriginalRunFailed || result.NoMutationsAttempted)
                {
                    // base case did not compile
                    Console.WriteLine($"// {inputFilePath}: {result}");
                }
                else
                {
                    int successes = variantTotal - variantFailedToCompile - variantFailedToRun;
                    Console.WriteLine($"// {inputFilePath}: {variantTotal} variants, {successes} passed" +
                        $" [{variantFailedToCompile} did not compile, {variantFailedToRun} did not run correctly]");
                }

                return -1;
            }
        }

        private ExecutionResult MutateOneTestFile(string testFile, ref int attempted, ref int failedToCompile, ref int failedToRun)
        {
            // Access input and build parse tree
            if (!File.Exists(testFile))
            {
                return new ExecutionResult() { kind = ExecutionResultKind.NoFileAccess };
            }

            bool hadFailures = false;

            string inputText = File.ReadAllText(testFile);
            string response = QueryLLMForMutation(inputText,
                @$"Please mutate this code {VersionLimit} times to introduce other C# language features.
Each mutation should be done to the previous version of the mutated code. Below are the rules for the mutations:

A loop is clonable if it contains array references and the loop bounds are loop invariant but not constants or the array length,
or if it includes a virtual or interface call on a variable that is not modified in the loop body.
Include several examples of clonable loops.
Try and reuse the same arrays in multiple loops.
Make sure to add appropriate using statements for any newly added types. 
Include control flow so that some of the loops execute only under certain conditions.
Do not use any sources of randomness or nondeterminisim in the new code.
Do not use nullable.
Remove any check for AVX512F.VL.
Add a checksum computation to the code to fingerprint the program behavior. 
The program must print the checksum value at some points during execution and at the end of the program.
Ensure that the checksum is not zero if the execution is successful and changes as the program progresses.
Rename any method with a [Fact] attribute to be the main entry point of a console application.
Do not modify the return code of the main method.

Return just the modified programs. Don't include any text in between each program in your response.");

            if (response == null)
            {
                return new ExecutionResult() { kind = ExecutionResultKind.BadLLMResponse };
            }

            string[] mutations = response.Split("```csharp");

            if (mutations.Length == 0)
            {
                return new ExecutionResult() { kind = ExecutionResultKind.BadLLMResponse };
            }

            for (int i = 1; i < mutations.Length; i++)
            {
                mutations[i] = mutations[i].Replace("```", string.Empty);
            }

            mutations[0] = inputText;

            for (int version = 0; version < mutations.Length; version++)
            {
                bool isMutant = true;
                attempted++;
                string mutatedText = mutations[version];

                string name = $"{Path.GetFileNameWithoutExtension(testFile)}-{version}";
                string mutantFile = Path.Join(Path.GetDirectoryName(testFile), name + ".cs");

                if (!_quiet)
                {
                    Console.WriteLine($"\n\n*** Version {version}: {name} *****");
                    Console.WriteLine(mutatedText);
                }

                File.WriteAllText(mutantFile, mutatedText);

                SyntaxTree mutatedTree = CSharpSyntaxTree.ParseText(mutatedText,
                        path: version == 0 ? testFile : $"{name}.cs",
                        options: ParseOptions);

                SyntaxTree[] mutatedTrees = { mutatedTree };

                CSharpCompilation debugCompilation = CSharpCompilation.Create(name, mutatedTrees, References, DebugOptions);
                (ExecutionResult debugResult, string debugstdout, string debugstderr) = CompileAndExecute(debugCompilation, name, isMutant);

                string debugOutFile = Path.Join(Path.GetDirectoryName(testFile), name + ".debug.out");
                File.WriteAllText(debugOutFile, $"### EXIT CODE {debugResult.value}\n### STDOUT\n{debugstdout}\n### STDERR\n{debugstderr}");
                

                if (debugResult.CompileFailed)
                {
                    failedToCompile++;
                    hadFailures = true;
                    Console.WriteLine($"*** {name} failed to compile *****");
                    continue;
                }

                if (debugResult.OriginalRunFailed || debugResult.MutantRunFailed)
                {
                    failedToRun++;
                    hadFailures = true;
                    Console.WriteLine($"*** {name} failed to run *****");

                    continue;
                }

                // Verify debug output is repeatable...

                (ExecutionResult debugResult1, string debugstdout1, string debugstderr1) = CompileAndExecute(debugCompilation, name, isMutant);

                string debugOutFile1 = Path.Join(Path.GetDirectoryName(testFile), name + ".debug.out.1");
                File.WriteAllText(debugOutFile1, $"### EXIT CODE {debugResult.value}\n### STDOUT\n{debugstdout}\n### STDERR\n{debugstderr}");

                if (debugstdout != debugstdout1 || debugstderr != debugstderr1)
                {
                    failedToRun++;
                    hadFailures = true;
                    Console.WriteLine($"*** {name} debug is non-determinsitic {debugOutFile} and {debugOutFile1} *****");
                    continue;
                }

                CSharpCompilation releaseCompilation = CSharpCompilation.Create(name, mutatedTrees, References, ReleaseOptions);
                (ExecutionResult releaseResult, string releasestdout, string releasestderr) = CompileAndExecute(releaseCompilation, name, isMutant);

                string releaseOutFile = Path.Join(Path.GetDirectoryName(testFile), name + ".release.out");
                File.WriteAllText(releaseOutFile, $"### EXIT CODE {releaseResult.value}\n### STDOUT\n{releasestdout}\n### STDERR\n{releasestderr}");

                // todo verify same outputs

                if (releaseResult.OriginalRunFailed || releaseResult.MutantRunFailed)
                {
                    failedToRun++;
                    hadFailures = true;
                    Console.WriteLine($"*** {name} debug/release fail difference, compare {debugOutFile} and {releaseOutFile} *****");
                    continue;
                }

                if (debugstdout != releasestdout || debugstderr != releasestderr)
                {
                    failedToRun++;
                    hadFailures = true;
                    Console.WriteLine($"*** {name} debug/release output difference, compare {debugOutFile} and {releaseOutFile} *****");
                    continue;
                }

                Console.WriteLine($"*** {name} debug/release matched");
            }

            if (hadFailures)
            {
                return new ExecutionResult() { kind = ExecutionResultKind.HadFailures };
            }
            else
            { 
                return new ExecutionResult() { kind = ExecutionResultKind.RanNormally };
            }
        }
        
        private string QueryLLMForMutation(string inputCode, string prompt)
        {
            try
            {
                Stopwatch stopwatch = new Stopwatch();
                stopwatch.Start();

                // Read the endpoint and API key from environment variables
                var endpoint = Environment.GetEnvironmentVariable("OPENAI_ENDPOINT")
                               ?? throw new InvalidOperationException("Environment variable 'OPENAI_ENDPOINT' is not set.");
                var apiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY")
                             ?? throw new InvalidOperationException("Environment variable 'OPENAI_API_KEY' is not set.");

                var deploymentName = "gpt-4.1";
                //var deploymentName = "o4-mini";
                var model = "o4-mini";

                AzureOpenAIClient azureClient = new(
                    new Uri(endpoint),
                    new AzureKeyCredential(apiKey));
                ChatClient chatClient = azureClient.GetChatClient(deploymentName);

                //var requestOptions = new ChatCompletionOptions()
                //{
                //    Model = model
                //};

                //requestOptions.

                List<ChatMessage> messages = new List<ChatMessage>()
                {
                    new SystemChatMessage("You are an expert C# programmer."),
                    new UserChatMessage("Here is a C# program."),
                    new UserChatMessage(inputCode),
                    new UserChatMessage(prompt)
                };

                var response = chatClient.CompleteChat(messages);

                stopwatch.Stop();
                Console.WriteLine($"LLM {deploymentName} query took {stopwatch.ElapsedMilliseconds} ms");

                return response.Value.Content[0].Text;

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error querying LLM: {ex.Message}");
                return null;
            }
        }

        private (ExecutionResult, string, string) CompileAndExecute(CSharpCompilation compilation, string name, bool isMutant = false)
        {
            string testAssemblyName = Path.Combine(Path.GetTempPath(), name + ".dll");
            string testDepsPath = Path.Combine(Path.GetTempPath(), name + ".deps.json");
            using (var ms = new FileStream(testAssemblyName, FileMode.Create, FileAccess.ReadWrite, FileShare.Read))
            {
                EmitResult emitResult;
                try
                {
                    emitResult = compilation.Emit(ms);
                }
                catch (Exception ex)
                {
                    if (!_quiet)
                    {
                        Console.WriteLine($"// Compilation of '{name}' failed: {ex.Message}");
                    }
                    return (new ExecutionResult() { kind = isMutant? ExecutionResultKind.MutantCompilationException : ExecutionResultKind.CompilationException }, "", "");
                }

                if (!emitResult.Success)
                {
                    if (!_quiet)
                    {
                        Console.WriteLine($"// Compilation of '{name}' failed: {emitResult.Diagnostics.Length} errors");
                        foreach (var d in emitResult.Diagnostics)
                        {
                            Console.WriteLine(d);
                        }
                    }
                    return (new ExecutionResult() { kind = isMutant ? ExecutionResultKind.MutantCompilationFailed : ExecutionResultKind.CompilationFailed }, "", "");
                }

                if (!_quiet)
                {
                    Console.WriteLine($"// Compiled '{name}' successfully into {testAssemblyName}");
                }

                ms.Close();

                var dependencyContext = new DependencyContext(
                    new TargetInfo(".NETCoreApp,Version=v10.0", "win10-x64", "win", true),
                    Microsoft.Extensions.DependencyModel.CompilationOptions.Default,
                    new CompilationLibrary[] { },
                    new RuntimeLibrary[] { },
                    new RuntimeFallbacks[] { }
                );

                using (var fileStream = new FileStream(testDepsPath, FileMode.Create, FileAccess.Write))
                {
                    var dependencyContextWriter = new DependencyContextWriter();
                    dependencyContextWriter.Write(dependencyContext, fileStream);
                }


                int result = -1;

                string standardOutput = string.Empty;
                string standardError = string.Empty;

                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = Path.Combine(Core_Root, "corerun.exe"),
                        // Arguments = $"{Path.Combine(Core_Root, "xunit.console.dll")} {testAssemblyName} -nologo -quiet",
                        Arguments = testAssemblyName,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                    };

                    psi.EnvironmentVariables["DOTNET_TieredCompilation"] = "0";

                    if (!_quiet)
                    {
                        Console.WriteLine($"// Running '{name}' via {psi.FileName} {psi.Arguments}");
                    }

                    // Start the process
                    using (Process process = Process.Start(psi))
                    {
                        // Read the standard output and error
                        standardOutput = process.StandardOutput.ReadToEnd();
                        standardError = process.StandardError.ReadToEnd();

                        // Wait for the process to exit
                        process.WaitForExit();

                        if (!_quiet)
                        {

                            // Display the captured output
                            Console.WriteLine("Standard Output:");
                            Console.WriteLine(standardOutput);

                            Console.WriteLine("Standard Error:");
                            Console.WriteLine(standardError);
                        }

                        result = process.ExitCode;

                        if (result != 0 && result != 100)
                        {
                            Console.WriteLine($"// Execution of '{name}' failed (exitCode {result})");
                            return (new ExecutionResult() { kind = isMutant ? ExecutionResultKind.MutantBadExitCode : ExecutionResultKind.BadExitCode, value = result }, standardOutput, standardError);
                        }

                        return (new ExecutionResult() { kind = ExecutionResultKind.RanNormally, value=result }, standardOutput, standardError);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"// Failed to start process: {ex.Message}");
                    return (new ExecutionResult() { kind = isMutant ? ExecutionResultKind.MutantThrewException : ExecutionResultKind.ThrewException , value = -1 }, standardOutput, standardError);
                }
            }
        }
    }
}
