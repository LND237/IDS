using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Media;

namespace Client
{
    public class Column
    {
        public string _name { get; set; }
        public int _value { get; set; }
        public Brush _colorBrush { get; set; }

        /// <summary>
        /// C'tor of class Column.
        /// </summary>
        /// <param name="name">The name of the column.</param>
        /// <param name="value">The value of the column.</param>
        /// <param name="colorBrush">The color of the column</param>
        public Column(string name, int value, Brush colorBrush)
        {
            _name = name;
            _value = value;
            _colorBrush = colorBrush;
        }

        /// <summary>
        /// The function gets the name of the column.
        /// </summary>
        /// <returns>The name.</returns>
        public string GetName()
        {
            return _name;
        }

        /// <summary>
        /// The function gets the value of the column.
        /// </summary>
        /// <returns>The value.</returns>
        public int GetValue()
        {
            return _value;
        }

        /// <summary>
        /// The function gets the color of the column.
        /// </summary>
        /// <returns>The color.</returns>
        public Brush GetColorBrush()
        {
            return _colorBrush;
        }

    }
}