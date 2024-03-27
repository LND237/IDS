using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DotNetEnv;

namespace Client
{
    internal class EnvFile
    {
        private const string RELATIVE_PATH = @"../../../../env_files/variables.env";
        
        /// <summary>
        /// The function extracts the username from the env file.
        /// </summary>
        /// <returns>The username</returns>
        public static string GetUsername()
        {
            string username = EnvFile.GetVariable(GetEnvFullDirectory(), "USERNAME_DB");
            return username;
        }

        /// <summary>
        /// The function extracts the password from the env file.
        /// </summary>
        /// <returns>The password</returns>
        public static string GetPassword()
        {
            string username = EnvFile.GetVariable(GetEnvFullDirectory(), "PASSWORD_DB");
            return username;
        }

        /// <summary>
        /// The function gets a value of a variable in the
        /// env file.
        /// </summary>
        /// <param name="path">The full path to the env file.</param>
        /// <param name="variableName">The name of the variable with the data
        /// in the env file.</param>
        /// <returns>The requested value</returns>
        private static string GetVariable(string path, string variableName)
        {
            string value = "";
            Env.Load(path);

            value = Environment.GetEnvironmentVariable(variableName);

            if (value != null)
            {
                return value;
            }
            return "";
        }

        /// <summary>
        /// The function gets the full path of the 
        /// env file.
        /// </summary>
        /// <returns>The full path</returns>
        private static string GetEnvFullDirectory()
        {
            // Get the directory of the executable
            string executableDirectory = AppDomain.CurrentDomain.BaseDirectory;

            // Combining the executable directory and the relative path to get the full path
            string envFilePath = Path.GetFullPath(Path.Combine(executableDirectory, RELATIVE_PATH));
            return envFilePath;
        }
    }
}
