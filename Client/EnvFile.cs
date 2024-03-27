using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DotNetEnv;

namespace Client
{
    public class EnvFile
    {
        private static readonly string PATH = GetEnvFullDirectory();

        /// <summary>
        /// The function gets a value of a variable in the
        /// env file.
        /// </summary>
        /// <param name="variableName">The name of the variable with the data
        /// in the env file.</param>
        /// <returns>The requested value</returns>
        private static string GetVariable(string variableName)
        {
            string value = "";
            Env.Load(PATH);

            value = Environment.GetEnvironmentVariable(variableName);

            if (value != null)
            {
                return value;
            }
            throw new ArgumentNullException();
        }

        /// <summary>
        /// The function gets the full path of the 
        /// env file.
        /// </summary>
        /// <returns>The full path</returns>
        private static string GetEnvFullDirectory()
        {
            const string RELATIVE_PATH = @"../../../../env_files/variables.env";

            // Get the directory of the executable
            string executableDirectory = AppDomain.CurrentDomain.BaseDirectory;

            // Combining the executable directory and the relative path to get the full path
            string envFilePath = Path.GetFullPath(Path.Combine(executableDirectory, RELATIVE_PATH));
            return envFilePath;
        }
    }
}
