using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Media;

namespace Client
{
    public class Category
    {
        public float _percentage { get; set; }
        public string _title { get; set; }
        public Brush _colorBrush { get; set; }

        /// <summary>
        /// C'tor class Category
        /// </summary>
        /// <param name="percentage">The precentage of the category</param>
        /// <param name="title">The title of the category</param>
        /// <param name="colorBrush">The color of the category.</param>
        public Category(float percentage, string title, Brush colorBrush)
        {
            _percentage = percentage;
            _title = title;
            _colorBrush = colorBrush;
        }

        /// <summary>
        /// The funciton gets the precentage of the category.
        /// </summary>
        /// <returns>The precentage.</returns>
        public float GetPrecentage()
        {
            return _percentage;
        }

        /// <summary>
        /// The function gets the title of the category.
        /// </summary>
        /// <returns>The title.</returns>
        public string GetTitle()
        {
            return _title;
        }

        /// <summary>
        /// The function gets the color of the category.
        /// </summary>
        /// <returns>The color.</returns>
        public Brush GetColorBrush()
        {
            return _colorBrush;
        }
    }
}